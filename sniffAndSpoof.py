#!/usr/bin/python3
from scapy.all import *

def spoof_pkt(pkt):
	# if the packet isn't an echo request, return
	if pkt[ICMP].type != 8:
		return

	# Spoof reply packet
	ip = IP(src=pkt[IP].dst, dst=pkt[IP].src, ihl=pkt[IP].ihl)
	icmp = ICMP(type=0, id=pkt[ICMP].id, seq=pkt[ICMP].seq)
	data = pkt[Raw].load
	newpkt = ip/icmp/data

	send(newpkt, verbose=0)

	print("Sent spoofed packet\n")

while(1):
	pkt = sniff(filter='icmp', prn=spoof_pkt)