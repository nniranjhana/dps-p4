#!/usr/bin/env python
from scapy.all import sendp, sendpfast, get_if_list, srpflood
from scapy.all import Ether, IP, TCP, UDP, DHCP, BOOTP
import random

def get_iface():
	iface = None
	for i in get_if_list(): # returns a list of connected hardware interfaces
		if "enp1s0f0" in i:
			iface = i
			break
	if not iface:
		print "Cannot find enp1s0f1 interface"
		exit(1)
	return iface

def main():
	iface = get_iface()
	hw = '00:00:00:00:01:01'
	print "sending on interface %s" % (iface)
	pkt = Ether(src = '00:00:00:00:01:01', dst = '00:00:00:00:01:02')

	pkt1 = pkt / IP(src='0.0.0.0', dst='10.0.1.2') / TCP(dport=1234, sport=random.randint(49152,65535)) # mal
	pkt2 = pkt / IP(src='0.0.0.0', dst='10.0.1.2') / UDP(dport=67, sport=68) / BOOTP(op = 1, chaddr = hw) / DHCP(options = [('message-type','discover'), ('end')]) # b
	pkt3 = pkt / IP(src='10.0.1.1',dst='10.0.1.2') / UDP(dport=67, sport=68) / BOOTP(op = 1, chaddr = hw) / DHCP(options = [('message-type','request'), ('end')]) # b
	pkt4 = pkt / IP(src='10.0.1.1',dst='10.0.1.2') / TCP(dport=1234, sport=random.randint(49152,65535)) # b
	pkt5 = pkt / IP(src='10.0.1.3', dst='10.0.1.2') / TCP(dport=1234, sport=random.randint(49152,65535)) # mal
	pkt6 = pkt / IP(src='10.0.1.5', dst='10.0.1.2') / TCP(dport=1234, sport=random.randint(49152,65535)) # mal

	pkts0 = [pkt2, pkt3, pkt4]
	pkts10 = [pkt1, pkt2, pkt3, pkt4, pkt2, pkt3, pkt4, pkt2, pkt3, pkt4]
	pkts25 = [pkt5, pkt2, pkt3, pkt4]
	pkts50 = [pkt1, pkt2, pkt4, pkt5]
	pkts75 = [pkt1, pkt2, pkt5, pkt6]
	pkts90 = [pkt1, pkt4, pkt5, pkt6, pkt1, pkt5, pkt6, pkt1, pkt6, pkt5]
	pkts100 = [pkt1, pkt5, pkt6]

	#srpflood(pkts0, iface=iface)
	#srpflood(pkts10, iface=iface)
	#srpflood(pkts25, iface=iface)
	#srpflood(pkts50, iface=iface)
	#srpflood(pkts75, iface=iface)
	#srpflood(pkts90, iface=iface)
	srpflood(pkts100, iface=iface)


if __name__ == '__main__':
	main()
