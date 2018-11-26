#!/usr/bin/env python
import hashlib
import os
import protocol
import socket
import struct
import sys
import threading
import time
from argparse import ArgumentParser
from protocol import AdbMessage


MAX_READ_COUNT = 4096 * 4096
# sleep 1 second after each empty packets, wait 1 hour in total
MAX_EMPTY_PACKETS = 360


def dump_file_data(addr, real_fname, data):
    fname = "data-%s.raw" % hashlib.sha256(data).hexdigest()
    if not os.path.exists(fname):
        print "%s\t%s\tfile:%s - dumping %s bytes of data to %s..." % (
            int(time.time()), str(addr).ljust(24), real_fname, len(data), fname)
        sys.stdout.flush()
        with open(fname, "wb") as f:
            f.write(data)


def send_message(conn, command, arg0, arg1, data):
    newmessage = AdbMessage(command, arg0, arg1, data)
    print ">>>>" + str(newmessage)
    conn.sendall(newmessage.encode())


def process_connection(conn, addr):
    states = []
    sending_binary = False
    dropped_file = ""
    empty_packets = 0
    filename = 'unknown'
    while True:
        debug_content = bytes()
        try:
            command = conn.recv(4)
            if not command:
                empty_packets += 1
                if empty_packets > MAX_EMPTY_PACKETS:
                    break
                # wait for more data
                time.sleep(1)
                continue
            empty_packets = 0
            debug_content += command
            arg1 = conn.recv(4)
            debug_content += arg1
            arg2 = conn.recv(4)
            debug_content += arg2
            data_length_raw = conn.recv(4)
            debug_content += data_length_raw
            data_length = struct.unpack("<L", data_length_raw)[0]
            data_crc = conn.recv(4)
            magic = conn.recv(4)
            data_content = bytes()

            if data_length > 0:
                # prevent reading the same stuff over and over again from some other attackers and locking the honeypot
                # max 1 byte read 64*4096 times (max packet length for ADB)
                read_count = 0

                while len(data_content) < data_length and read_count < MAX_READ_COUNT:
                    read_count += 1
                    # don't overread the content of the next data packet
                    bytes_to_read = data_length - len(data_content)
                    data_content += conn.recv(bytes_to_read)

            else:
                pass
            # check integrity of read data
            if len(data_content) < data_length:
                # corrupt content, abort the connection (probably not an ADB client)
                break
            # assemble a full data packet as per ADB specs
            data = command + arg1 + arg2 + data_length_raw + data_crc + magic + data_content
        except Exception as ex:
            print '%s\t%s\t %s : %s' % (int(time.time()), str(addr).ljust(24), repr(ex), repr(debug_content))
            break

        try:
            message = AdbMessage.decode(data)[0]
            # print message
            string = str(message)
            if len(string) > 96:
                print "<<<<%s ...... %s" % (string[0:64], string[-32:])
            else:
                print "<<<<%s" % string
        except Exception as e:
            # don't print anything, a lot of garbage coming in usually, just drop the connection
            break

        # keep a record of all the previous states in order to handle some weird cases
        states.append(message.command)

        # corner case for binary sending
        if sending_binary:
            # look for that shitty DATAXXXX where XXXX is the length of the data block that's about to be sent
            # (i.e. DATA\x00\x00\x01\x00)
            if message.command == protocol.CMD_WRTE and "DATA" in message.data:
                data_index = message.data.index("DATA")
                payload_fragment = message.data[:data_index] + message.data[data_index + 8:]
                dropped_file += payload_fragment
            elif message.command == protocol.CMD_WRTE:
                dropped_file += message.data

            # truncate
            if "DONE" in message.data:
                dropped_file = dropped_file[:-8]
                sending_binary = False
                dump_file_data(addr, filename, dropped_file)
                # ADB has a shitty state machine, sometimes we need to send duplicate messages
                send_message(conn, protocol.CMD_WRTE, 2, message.arg0, "OKAY")
                send_message(conn, protocol.CMD_WRTE, 2, message.arg0, "OKAY")
                send_message(conn, protocol.CMD_OKAY, 2, message.arg0, "")
                send_message(conn, protocol.CMD_OKAY, 2, message.arg0, "")

                continue
            if message.command != protocol.CMD_WRTE:
                dropped_file += data

            send_message(conn, protocol.CMD_OKAY, 2, message.arg0, "")
            send_message(conn, protocol.CMD_OKAY, 2, message.arg0, "")
            continue

        # regular flow
        if not sending_binary:
            # look for the data header that is first sent when initiating a data connection
            '''  /sdcard/stuff/exfiltrator-network-io.PNG,33206DATA '''
            if "DATA" in message.data[:128]:
                sending_binary = True
                dropped_file = ""
                seq_number = 1
                # if the message is really short, wrap it up
                if "DONE" in message.data[-8:]:
                    sending_binary = False
                    predata = message.data.split("DATA")[0]
                    if predata:
                        filename = predata.split(",")[0]

                    dropped_file = message.data.split("DATA")[1][4:-8]
                    send_message(conn, protocol.CMD_WRTE, 2, message.arg0, "OKAY")
                    send_message(conn, protocol.CMD_WRTE, 2, message.arg0, "OKAY")

                    send_message(conn, protocol.CMD_OKAY, 2, message.arg0, "")
                    send_message(conn, protocol.CMD_OKAY, 2, message.arg0, "")

                    dump_file_data(addr, filename, dropped_file)
                    continue
                else:
                    predata = message.data.split("DATA")[0]
                    if predata:
                        filename = predata.split(",")[0]
                    dropped_file = message.data.split("DATA")[1][4:]

                send_message(conn, protocol.CMD_OKAY, 2, message.arg0, "")
                send_message(conn, protocol.CMD_OKAY, 2, message.arg0, "")
                continue

            if len(states) >= 2 and states[-2:] == [protocol.CMD_WRTE, protocol.CMD_WRTE]:
                # last block of messages before the big block of data
                filename = message.data
                send_message(conn, protocol.CMD_OKAY, 2, message.arg0, "")
                # why do I have to send the command twice??? science damn it!
                send_message(conn, protocol.CMD_WRTE, 2, message.arg0, "STAT\x07\x00\x00\x00")
                send_message(conn, protocol.CMD_WRTE, 2, message.arg0, "STAT\x07\x00\x00\x00")
            elif len(states) > 2 and states[-2:] == [protocol.CMD_OKAY, protocol.CMD_WRTE]:
                send_message(conn, protocol.CMD_OKAY, 2, message.arg0, "")
                # send_message(conn, protocol.CMD_WRTE, 2, message.arg0, "FAIL")
            elif len(states) > 1 and states[-2:] == [protocol.CMD_OPEN, protocol.CMD_WRTE]:
                send_message(conn, protocol.CMD_OKAY, 2, message.arg0, "")
                if len(message.data) > 8:
                    send_message(conn, protocol.CMD_WRTE, 2, message.arg0, "STAT\x01\x00\x00\x00")
                    send_message(conn, protocol.CMD_WRTE, 2, message.arg0, "STAT\x01\x00\x00\x00")
                    filename = message.data[8:]
            elif states[-1] == protocol.CMD_OPEN and "shell" in message.data:
                send_message(conn, protocol.CMD_OKAY, 2, message.arg0, "")
                # change the WRTE contents with whatever you'd like to send to the attacker
                send_message(conn, protocol.CMD_WRTE, 2, message.arg0, "")
                send_message(conn, protocol.CMD_CLSE, 2, message.arg0, "")
                # print the shell command that was sent
                # also remove trailing \00
                print "%s\t%s\t%s" % (int(time.time()), str(addr).ljust(24), message.data[:-1])
                # wanna see the shell command ASAP
                sys.stdout.flush()

            elif states[-1] == protocol.CMD_CNXN:
                send_message(conn, protocol.CMD_CNXN, 0x01000000, 4096,
                             "device::http://ro.product.name =starltexx;ro.product.model=SM-G960F;ro.product.device=starlte;features=cmd,stat_v2,shell_v2")
            elif states[-1] == protocol.CMD_OPEN and "sync" not in message.data:
                send_message(conn, protocol.CMD_OKAY, 2, message.arg0, "")
            elif states[-1] == protocol.CMD_OPEN:
                send_message(conn, protocol.CMD_OKAY, 2, message.arg0, "")
            elif states[-1] == protocol.CMD_CLSE and not sending_binary:
                send_message(conn, protocol.CMD_CLSE, 2, message.arg0, "")
            elif states[-1] == protocol.CMD_WRTE and "QUIT" in message.data:
                send_message(conn, protocol.CMD_OKAY, 2, message.arg0, "")
                send_message(conn, protocol.CMD_CLSE, 2, message.arg0, "")
    conn.close()


def main_coonection_loop(bind_addr, bind_port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    """ Set TCP keepalive on an open socket.

        It activates after 1 second (after_idle_sec) of idleness,
        then sends a keepalive ping once every 1 seconds (interval_sec),
        and closes the connection after 100 failed ping (max_fails)
    """
    s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    if hasattr(socket, 'TCP_KEEPIDLE'):
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 1)
    elif hasattr(socket, 'TCP_KEEPALIVE'):
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPALIVE, 1)
    if hasattr(socket, 'TCP_KEEPINTVL'):
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 1)
    if hasattr(socket, 'TCP_KEEPCNT'):
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 100)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)
    s.bind((bind_addr, bind_port))
    s.listen(1)
    print 'Listening on %s:%d.' % (bind_addr, bind_port)
    try:
        while True:
            conn, addr = s.accept()
            print '%s\t%s\t + connection start' % (int(time.time()), str(addr).ljust(24))
            threading.Thread(target=process_connection, args=(conn, addr)).start()

    except KeyboardInterrupt:
        s.close()
        print 'Exiting...'


if __name__ == '__main__':

    addr = '0.0.0.0'
    port = 5555

    parser = ArgumentParser(description='ADBHoney', add_help=True)
    parser.add_argument('--addr', type=str, help='Address where bind to')
    parser.add_argument('--port', type=str, help='Port to listen')

    args = parser.parse_args()

    if args.addr:
        addr = args.addr

    if args.port:
        port = int(args.port)

    main_coonection_loop(addr, port)
