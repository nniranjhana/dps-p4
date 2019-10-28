#!/usr/bin/env python
import sys
import os

from scapy.all import sniff, sendp, get_if_list, get_if_hwaddr, get_if_raw_hwaddr
from scapy.all import Ether, ARP

def send_response(pkt):
	client_hw_addr = pkt[Ether].src
	client_ip_addr = pkt[ARP].psrc
	print "request detected from client with MAC: %s and IP: %s" % (client_hw_addr, client_ip_addr)

	ifaces = filter(lambda i: 'eth' in i, os.listdir('/sys/class/net/'))
	iface = ifaces[0]

	print "sending response packet from interface %s" % iface
	rpkt = Ether(src = get_if_hwaddr(iface), dst = client_hw_addr)
	rpkt = rpkt / ARP(op = 2, hwsrc = get_if_hwaddr(iface), hwdst = client_hw_addr, pdst = client_ip_addr)
	rpkt.show2()
	sendp(rpkt, iface = iface, verbose = False) # sendp works at layer 2
	exit(1)

def handle_pkt(pkt):
	if ARP in pkt:
		print "got an ARP packet"
	pkt.show2()
	send_response(pkt)

def main():
	ifaces = filter(lambda i: 'eth' in i, os.listdir('/sys/class/net/'))
	iface = ifaces[0]
	print "sniffing on %s" % iface
	sys.stdout.flush()
	sniff(iface = iface,
		prn = lambda x: handle_pkt(x))
	# sniff function passes the packet object as the one arg into prn: func

if __name__ == '__main__':
	main()