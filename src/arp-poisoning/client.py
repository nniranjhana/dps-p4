#!/usr/bin/env python
from scapy.all import sendp, get_if_list, get_if_hwaddr, get_if_raw_hwaddr
from scapy.all import Ether, ARP

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
	pkt = pkt / ARP(op = 1, hwsrc = hw, hwdst = 'ff:ff:ff:ff:ff:ff', pdst = '255.255.255.255')
	pkt.show2() # for a developed view of the assembled packet
	sendp(pkt, iface = iface, verbose = False) # sendp works at layer 2
	exit(1)

if __name__ == '__main__':
	main()