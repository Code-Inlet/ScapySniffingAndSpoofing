#!/usr/bin/python3
from scapy.all import *

ip = IP()
ip.dst = '10.0.2.4'
ip.src = '1.2.3.4'

icmp = ICMP()

packet = ip/icmp

send(packet)
