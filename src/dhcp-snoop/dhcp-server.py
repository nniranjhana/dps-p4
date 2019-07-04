#!/usr/bin/env python
import sys
import struct
import os

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_raw_hwaddr
from scapy.all import Packet, IPOption
from scapy.all import ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import IP, UDP, Raw
from scapy.layers.inet import _IPOption_HDR

def handle_pkt(pkt):
	if UDP in pkt and pkt[UDP].dport == 67:
		print "got a DHCP packet"
		pkt.show2()
		sys.stdout.flush()

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