#!/usr/bin/env python

from scapy.all import sendp, get_if_list, get_if_hwaddr, get_if_raw_hwaddr
from scapy.all import Ether, ARP

def get_iface():
	iface = None
	for i in get_if_list():
		if "eth0" in i:
			iface = i
			break
	if not iface:
		print "Cannot find eth0 interface"
		exit(1)
	return iface

def main():

	iface = get_iface()
	fam, hw = get_if_raw_hwaddr(iface)

	print "sending on interface %s" % (iface)
	pkt = Ether(src = get_if_hwaddr(iface), dst = 'ff:ff:ff:ff:ff:ff')
	
	# A spoofed ARP packet with modified src protocol (IP) address
	pkt = pkt / ARP(op = 2, hwsrc = hw, psrc = '10.0.1.2', hwdst = 'ff:ff:ff:ff:ff:ff', pdst = '255.255.255.255')
	pkt.show2() # for a developed view of the assembled packet
	sendp(pkt, iface = iface, verbose = False) # sendp works at layer 2)

if __name__ == '__main__':
	main()