#!/usr/bin/env python
from scapy.all import sendp, get_if_list, get_if_hwaddr, get_if_raw_hwaddr
from scapy.all import Ether, IP, TCP, UDP, DHCP, BOOTP
import random

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

	iface = get_iface()
	fam, hw = get_if_raw_hwaddr(iface) # returns family and hardware address of the interface

	print "sending on interface %s" % (iface)
	pkt = Ether(src = get_if_hwaddr(iface), dst = 'ff:ff:ff:ff:ff:ff')

	# pkt 1: a non-DHCP pkt with src IP 0.0.0.0 to simulate a client which hasn't been assigned IP addr yet
	# DROPPED
	pkt1 = pkt / IP(src='0.0.0.0', dst='255.255.255.255') / TCP(dport=1234, sport=random.randint(49152,65535))
	pkt1.show2() # for a developed view of the assembled packet
	sendp(pkt1, iface = iface, verbose = False) # sendp works at layer 2

	# pkt 2: a DHCP discover pkt with src IP 0.0.0.0
	# FORWARDED
	pkt2 = pkt / IP(src='0.0.0.0', dst='255.255.255.255') / UDP(dport=67, sport=68) / BOOTP(op = 1, chaddr = hw) / DHCP(options = [('message-type','discover'), ('end')])
	pkt2.show2()
	sendp(pkt2, iface = iface, verbose = False)

	# pkt 3: a DHCP request pkt with its original src IP
	# FORWARDED
	pkt3 = pkt / IP(dst='255.255.255.255') / UDP(dport=67, sport=68) / BOOTP(op = 1, chaddr = hw) / DHCP(options = [('message-type','request'), ('end')])
	pkt3.show2()
	sendp(pkt3, iface = iface, verbose = False)

	# pkt 4: a non-DHCP pkt with its original src IP
	# FORWARDED
	pkt4 = pkt / IP(dst='255.255.255.255') / TCP(dport=1234, sport=random.randint(49152,65535))
	pkt4.show2()
	sendp(pkt4, iface = iface, verbose = False)

	# pkt 5: a non-DHCP pkt with spoofed src IP 10.0.1.3, which doesn't exist in the DHCP bindings table
	# DROPPED
	pkt5 = pkt / IP(src='10.0.1.3', dst='255.255.255.255') / TCP(dport=1234, sport=random.randint(49152,65535))
	pkt5.show2()
	sendp(pkt5, iface = iface, verbose = False)

if __name__ == '__main__':
	main()
