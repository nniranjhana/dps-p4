#!/usr/bin/env python

from scapy.all import sendp, get_if_list, get_if_hwaddr, get_if_raw_hwaddr
from scapy.all import Ether, IP, UDP, DHCP, BOOTP

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
	pkt = pkt / IP(dst = '255.255.255.255') / UDP(dport = 67, sport = 68) / BOOTP(op = 1, chaddr = hw) / DHCP(options = [('message-type','request'), ('end')])
	pkt.show2()
	# Send a broadcast packet from this unknown client MAC address not present in the DHCP bindings table
	sendp(pkt, iface = iface, verbose = False)

	pkt = Ether(src = get_if_hwaddr(iface), dst = '00:00:00:00:01:01')
	pkt = pkt / IP(dst = '10.0.1.1') / UDP(dport = 68, sport = 67) / BOOTP(op = 2, chaddr = hw) / DHCP(options = [('message-type', 'ack'), ('end')])
	pkt.show2()
	# Send an ack packet from untrusted server not presented in the DHCP trusted server IP table
	sendp(pkt, iface = iface, verbose = False)

if __name__ == '__main__':
	main()
