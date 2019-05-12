#!/usr/bin/env python2

from __future__ import print_function
from argparse import ArgumentParser
from datetime import datetime
from responses import cmd_responses
import threading
import binascii
import protocol
import hashlib
import logging
import socket
import struct
import json
import time
import sys
import os

__version__ = '1.00'

MAX_READ_COUNT = 4096 * 4096
# sleep 1 second after each empty packets, wait 1 hour in total
MAX_EMPTY_PACKETS = 360
DEVICE_ID = 'device::http://ro.product.name =starltexx;ro.product.model=SM-G960F;ro.product.device=starlte;features=cmd,stat_v2,shell_v2'


FORMAT = "%(asctime)s - %(thread)s - %(name)s - %(levelname)s - %(message)s"
logging.basicConfig(level=logging.DEBUG, format=FORMAT)
logger = logging.getLogger('ADBHoneypot')

CONFIG = {}

class ADBConnection(threading.Thread):
    def __init__(self, conn, addr, CONFIG):
        threading.Thread.__init__(self)
        self.conn = conn
        self.addr = addr
        self.CONFIG = CONFIG
        self.run()

    def run(self):
        logger.debug("Processing new connection!")
        self.process_connection()

    def send_message(self, command, arg0, arg1, data):
        newmessage = protocol.AdbMessage(command, arg0, arg1, data)
        logger.info('sending: {}'.format(newmessage))
        self.conn.sendall(newmessage.encode())

    def send_twice(self, command, arg0, arg1, data):
        self.send_message(command, arg0, arg1, data)
        self.send_message(command, arg0, arg1, data)

    def recv_data(self):
        debug_content = bytes()
        empty_packets = 0
        try:
            command = self.conn.recv(4)
            if not command:
                empty_packets += 1
                if empty_packets > MAX_EMPTY_PACKETS:
                    return None
                # wait for more data
                time.sleep(1)
                return None
            #logger.info("Received command {}".format(command))
            empty_packets = 0
            arg1 = self.conn.recv(4)
            #logger.info("Received arg 1 {}".format(arg1))
            arg2 = self.conn.recv(4)
            #logger.info("Received arg 2 {}".format(arg2))
            data_length_raw = self.conn.recv(4)
            #logger.info("Received data_length_raw {}".format(data_length_raw))
            data_length = struct.unpack('<L', data_length_raw)[0]
            #logger.info("unpacked data length {}".format(data_length))
            data_crc = self.conn.recv(4)
            #logger.info("Received data_crc {}".format(data_crc))
            magic = self.conn.recv(4)
            #logger.info("Received magic {}".format(magic))

            data_content = bytes()

            if data_length > 0:
                # prevent reading the same stuff over and over again from some other attackers and locking the honeypot
                # max 1 byte read 64*4096 times (max packet length for ADB)
                read_count = 0

                while len(data_content) < data_length and read_count < MAX_READ_COUNT:
                    read_count += 1
                    # don't overread the content of the next data packet
                    bytes_to_read = data_length - len(data_content)
                    data_content += self.conn.recv(bytes_to_read)
            # check integrity of read data
            if len(data_content) < data_length:
                logger.error("data content length is greater than data_length, corrupt data!!")
                # corrupt content, abort the self.connection (probably not an ADB client)
                data = None
            else:
                # assemble a full data packet as per ADB specs
                data = command + arg1 + arg2 + data_length_raw + data_crc + magic + data_content
        except Exception as e:
            logger.info("Connection reset by peer.")
            raise EOFError
            #logger.error("{} : {}".format(self.addr[0], e))
            #raise
        return data
    
    def parse_data(self, data):
        try:
            message = protocol.AdbMessage.decode(data)[0]
            #logger.info("decoded message {}".format(message))
            string = str(message)
            if len(string) > 96:
                logger.info('<<<<{} ...... {}'.format(string[0:64], string[-32:]))
            else:
                logger.info('<<<<{}'.format(string))
            return message
        except Exception as e:
            logger.error(e)
            # don't print anything, a lot of garbage coming in usually, just drop the connection
            raise
        #return None

    def dump_file_data(self, filename, data):
        print(type(data))
        shasum = hashlib.sha256(data.encode()).hexdigest()
        fname = 'data-{}.raw'.format(shasum)
        if CONFIG['download_dir'] and not os.path.exists(CONFIG['download_dir']):
            os.makedirs(CONFIG['download_dir'])
        fullname = os.path.join(CONFIG['download_dir'], fname)
        logger.info('file: {} - dumping {} bytes of data to {}'.format(filename, len(data), fullname))
#        obj = {
#            'eventid': 'adbhoney.session.file_upload',
#            'timestamp': getutctime(),
#            'unixtime': int(time.time()),
#            'session': session,
#            'message': 'Downloaded file with SHA-256 {} to {}'.format(shasum, fullname),
#            'src_ip': addr[0],
#            'shasum': shasum,
#            'outfile': fullname,
#            'sensor': CONFIG['sensor']
#        }
#        jsonlog(obj, CONFIG)
        if not os.path.exists(fullname):
            with open(fullname, 'wb') as f:
                f.write(data)

    def binary_send_corner_case(self, message, data, dropped_file):
        logger.info("Entering binary_send_corner_case")
        filename = 'unknown'
        # look for that shitty DATAXXXX where XXXX is the length of the data block that's about to be sent
        # (i.e. DATA\x00\x00\x01\x00)
        if message.command == protocol.CMD_WRTE and 'DATA' in message.data:
            data_index = message.data.index('DATA')
            payload_fragment = message.data[:data_index] + message.data[data_index + 8:]
            dropped_file += payload_fragment
        elif message.command == protocol.CMD_WRTE:
            dropped_file += message.data

        # truncate
        if 'DONE' in message.data:
            dropped_file = dropped_file[:-8]
            self.sending_binary = False
            self.dump_file_data(filename, dropped_file)
            # ADB has a shitty state machine, sometimes we need to send duplicate messages
            self.send_twice(protocol.CMD_WRTE, 2, message.arg0, 'OKAY')
            #send_message(conn, protocol.CMD_WRTE, 2, message.arg0, 'OKAY', CONFIG)
            self.send_twice(protocol.CMD_OKAY, 2, message.arg0, '')
            #send_message(conn, protocol.CMD_OKAY, 2, message.arg0, '', CONFIG)

        if message.command != protocol.CMD_WRTE:
            dropped_file += data

        self.send_twice(protocol.CMD_OKAY, 2, message.arg0, '')
        return dropped_file
        #send_message(conn, protocol.CMD_OKAY, 2, message.arg0, '', CONFIG)


    def recv_binary(self, message, dropped_file):
        logger.info("Entering recv_binary")
        self.sending_binary = True
        # if the message is really short, wrap it up
        if 'DONE' in message.data[-8:]:
            self.sending_binary = False
            predata = message.data.split('DATA')[0]
            if predata:
                filename = predata.split(',')[0]

            dropped_file = message.data.split('DATA')[1][4:-8]
            self.send_twice(protocol.CMD_WRTE, 2, message.arg0, 'OKAY')
            self.send_message(protocol.CMD_OKAY, 2, message.arg0, '')

            self.dump_file_data(filename, dropped_file)
        else:
            predata = message.data.split('DATA')[0]
            if predata:
                filename = predata.split(',')[0]
            dropped_file = message.data.split('DATA')[1][4:]
        logger.info("last line in recv_binary")
        #self.send_message(protocol.CMD_OKAY, 2, message.arg0, '')

    def recv_shell_cmd(self, message):
        logger.info("Entering recv_shell_cmd")
        self.send_message(protocol.CMD_OKAY, 2, message.arg0, '')

        cmd = message.data.split(':')[1][:-1]
        # change the WRTE contents with whatever you'd like to send to the attacker
        logger.info("shell command is {}, len {}".format(cmd, len(cmd)))
        if cmd in cmd_responses:
            response = cmd_responses[cmd]
        else:
            response = "{}: command not found\n".format(cmd)

        self.send_message(protocol.CMD_WRTE, 2, message.arg0, response)
        self.send_message(protocol.CMD_CLSE, 2, message.arg0, '')
        # print the shell command that was sent
        # also remove trailing \00
        logger.info('{}\t{}'.format(self.addr[0], message.data[:-1]))
#        obj = {
#            'eventid': 'adbhoney.command.input',
#            'timestamp': getutctime(),
#            'unixtime': int(time.time()),
#            'session': session,
#            'message': message.data[:-1],
#            'src_ip': addr[0],
#            'input': message.data[6:-1],
#            'sensor': CONFIG['sensor']
#        }

    def process_connection(self):
        start = time.time()
        self.session = binascii.hexlify(os.urandom(6))
        localip = socket.gethostbyname(socket.gethostname())
        logger.info('{} connection start ({})'.format(self.addr[0], self.session))
#        obj = {
#            'eventid': 'adbhoney.session.connect',
#            'timestamp': datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
#            'unixtime': int(start),
#            'session': self.session,
#            'message': 'New connection: {}:{} ({}:{}) [session: {}]'.format(addr[0], addr[1], localip, CONFIG['port'], session),
#            'src_ip': addr[0],
#            'src_port': addr[1],
#            'dst_ip': localip,
#            'dst_port': CONFIG['port'],
#            'sensor': CONFIG['sensor']
#        }

        states = []
        self.sending_binary = False
        dropped_file = ''
        filename = 'unknown'
        closedmessage = 'Connection closed'
        while True:
            try:
                data = self.recv_data()
                #logger.info("received data...")
            except EOFError:
                break
            if not data:
                logger.info("data is none?: {}".format(data))
                break
                #continue
            message = self.parse_data(data)
            if type(message.data) == bytes:
                message.data = message.data.decode()
            # keep a record of all the previous states in order to handle some weird cases
            states.append(message.command)

            # corner case for binary sending
            if self.sending_binary:
                logger.info("corner case?? just large binary")
                dropped_file = self.binary_send_corner_case(message, data, dropped_file)
                continue
            # look for the data header that is first sent when initiating a data connection
            #  /sdcard/stuff/exfiltrator-network-io.PNG,33206DATA
            elif 'DATA' in message.data[:128]:
                logger.info("receiving binary....")
                self.recv_binary(message, dropped_file)
                continue
            else:   # regular flow
                if len(states) >= 2 and states[-2:] == [protocol.CMD_WRTE, protocol.CMD_WRTE]:
                    logger.debug("Received Write/Write")
                    # last block of messages before the big block of data
                    filename = message.data
                    self.send_message(protocol.CMD_OKAY, 2, message.arg0, '')
                    # why do I have to send the command twice??? science damn it!
                    self.send_twice(protocol.CMD_WRTE, 2, message.arg0, 'STAT\x07\x00\x00\x00')
                elif states[-1] == protocol.CMD_WRTE and 'QUIT' in message.data:
                    logger.debug("Received quit command.")
                    #self.send_message(protocol.CMD_OKAY, 2, message.arg0, '')
                    self.send_message(protocol.CMD_CLSE, 2, message.arg0, '')
                elif len(states) > 2 and states[-2:] == [protocol.CMD_OKAY, protocol.CMD_WRTE]:
                    logger.debug("Received Okay/Write")
                    self.send_message(protocol.CMD_OKAY, 2, message.arg0, '')
                    # self.send_message(conn, protocol.CMD_WRTE, 2, message.arg0, 'FAIL', CONFIG)
                elif len(states) > 2 and states[-2:] == [protocol.CMD_WRTE, protocol.CMD_OKAY]:
                    logger.debug("Received Write/Okay")
                    self.send_message(protocol.CMD_OKAY, 2, message.arg0, '')
                    # self.send_message(conn, protocol.CMD_WRTE, 2, message.arg0, 'FAIL', CONFIG)
                elif len(states) > 1 and states[-2:] == [protocol.CMD_OPEN, protocol.CMD_WRTE]:
                    logger.debug("Received Open/Write")
                    self.send_message(protocol.CMD_OKAY, 2, message.arg0, '')
                    if len(message.data) > 8:
                        self.send_twice(protocol.CMD_WRTE, 2, message.arg0, 'STAT\x01\x00\x00\x00')
                        filename = message.data[8:]
                elif states[-1] == protocol.CMD_OPEN and 'shell' in message.data:
                    logger.debug("Received shell command.")
                    self.recv_shell_cmd(message)
                elif states[-1] == protocol.CMD_CNXN:
                    logger.debug("Received connection command.")
                    self.send_message(protocol.CMD_CNXN, 0x01000000, 4096, DEVICE_ID)
                elif states[-1] == protocol.CMD_OPEN and 'sync' not in message.data:
                    logger.debug("Received sync command.")
                    self.send_message(protocol.CMD_OKAY, 2, message.arg0, '')
                elif states[-1] == protocol.CMD_OPEN:
                    logger.debug("Received open command.")
                    self.send_message(protocol.CMD_OKAY, 2, message.arg0, '')
                elif states[-1] == protocol.CMD_CLSE and not self.sending_binary:
                    logger.debug("Received close command, 1.")
                    #self.send_message(protocol.CMD_CLSE, 2, message.arg0, '')
        duration = time.time() - start
        logger.info('{}\t{}\tconnection closed'.format(duration, self.addr[0]))
#        obj = {
#            'eventid': 'adbhoney.session.closed',
#            'timestamp': getutctime(),
#            'unixtime': int(time.time()),
#            'session': session,
#            'message': '{} after {} seconds'.format(closedmessage, int(round(duration))),
#            'src_ip': addr[0],
#            'duration': duration,
#            'sensor': CONFIG['sensor']
#        }
        self.conn.close()

class ADBHoneyPot:
    def __init__(self):
        self.bind_addr = '127.0.0.1'
        self.bind_port = 5555
        self.download_dir = 'dl/'
        self.logfile = None
        self.debug = False
        self.sensor = socket.gethostname()

    def accept_connections(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        """ Set TCP keepalive on an open socket.

            It activates after 1 second (after_idle_sec) of idleness,
            then sends a keepalive ping once every 1 seconds (interval_sec),
            and closes the connection after 100 failed ping (max_fails)
        """
        #self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # pylint: disable=no-member
        if hasattr(socket, 'TCP_KEEPIDLE'):
            self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 1)
        elif hasattr(socket, 'TCP_KEEPALIVE'):
            self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPALIVE, 1)
        if hasattr(socket, 'TCP_KEEPINTVL'):
            self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 1)
        if hasattr(socket, 'TCP_KEEPCNT'):
            self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 100)
        # pylint: enable=no-member
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)
        self.sock.bind((self.bind_addr, self.bind_port))
        self.sock.listen(1)
        logger.info('Listening on {}:{}.'.format(self.bind_addr, self.bind_port))
        try:
            while True:
                conn, addr = self.sock.accept()
                logger.info("Received a connection, creating an ADBConnection.")
                thread = threading.Thread(target=ADBConnection, args=(conn, addr, CONFIG))
                thread.daemon = True
                logger.info("Starting ADBConnection")
                thread.start()
        except KeyboardInterrupt:
            logger.info('Exiting...')
            self.sock.close()

if __name__ == '__main__':
    # Eventually these will be filled from a config file
    CONFIG['addr'] = '127.0.0.1'
    CONFIG['port'] = 5555
    CONFIG['download_dir'] = ''
    CONFIG['logfile'] = None
    CONFIG['json_log'] = None
    CONFIG['sensor'] = socket.gethostname()
    CONFIG['debug'] = False

    parser = ArgumentParser()
    parser.add_argument('-v', '--version', action='version', version="%(prog)s" + __version__)
    parser.add_argument('-a', '--addr', type=str, default=CONFIG['addr'], help='Address to bind to (default: {})'.format(CONFIG['addr']))
    parser.add_argument('-p', '--port', type=int, default=CONFIG['port'], help='Port to listen on (default: {})'.format(CONFIG['port']))
    parser.add_argument('-d', '--dlfolder', type=str, default='', help='Directory for the uploaded samples (default: current)')
    parser.add_argument('-l', '--logfile', type=str, default=None, help='Log file (default: stdout')
    parser.add_argument('-j', '--jsonlog', type=str, default=None, help='JSON log file')
    parser.add_argument('-s', '--sensor', type=str, default=CONFIG['sensor'], help='Sensor name (default: {})'.format(CONFIG['sensor']))
    parser.add_argument('--debug', action='store_true', help='Produce verbose output')

    args = parser.parse_args()

    CONFIG['addr'] = args.addr
    CONFIG['port'] = args.port
    CONFIG['download_dir'] = args.dlfolder
    CONFIG['logfile'] = args.logfile
    CONFIG['json_log'] = args.jsonlog
    CONFIG['sensor'] = args.sensor
    CONFIG['debug'] = args.debug

    honeypot = ADBHoneyPot()
    honeypot.accept_connections()
