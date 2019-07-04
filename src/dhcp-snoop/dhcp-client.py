#!/usr/bin/env python
import argparse
import sys
import socket
import struct

from scapy.all import sendp, send, get_if_list, get_if_raw_hwaddr, conf, sniff
from scapy.all import Packet
from scapy.all import Ether, IP, UDP, DHCP, BOOTP

def get_iface():
	iface = None
	for i in get_if_list(): # returns a list of connected hardware interfaces
		if "eth0" in i:
			iface = i
			break
	if not iface:
		print "Cannot find eth0 interface"
		exit(1)
	return iface

def main():

	if len(sys.argv) < 3:
		print 'pass 2 arguments: <destination> "<message>"'
		exit(1)

	addr = socket.gethostbyname(sys.argv[1]) # the destination IP address entered by the user
	iface = get_iface()
	fam, hw = get_if_raw_hwaddr(iface) # returns family and hardware address of the interface

	print "sending on interface %s to %s" % (iface, str(addr))
	pkt = Ether(src = get_if_hwaddr(iface), dst = 'ff:ff:ff:ff:ff:ff')
	# Assembling a DHCP discover message
	pkt = pkt /IP(dst = addr) /UDP(dport = 67, sport = 68) /BOOTP(op = 1, chaddr = hw /DHCP(options = [('message-type','discover'), ('end')])) / sys.argv[2]
	pkt.show2() # for a developed view of the assembled packet
	sendp(pkt, iface = iface, verbose = True) # sendp works at layer 2

if __name__ == '__main__':
	main()