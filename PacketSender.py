"""
TO-TO:

- Create Packet sender that can send packets 
- Ability to replicate DDOS to show that firewall can block it
"""

import sys
import time
from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.l2 import Ether

NUM_PACKETS = 100
DURATION = 5

def send_packets(target_ip, interface, num_packets, duration):
    packet = Ether() / IP(dst=target_ip) / TCP()
    end_time = time.time() + duration
    packet_count = 0

    while time.time() < end_time and packet_count < num_packets:
        sendp(packet, iface=interface)
        packet_count += 1

if __name__ == "__main__":
    if sys.version_info[0] < 3:
        print("This script requires Python 3.")
        sys.exit(1)

    # ip = input("What is the target IP for this device?")

    # interface = input("What is the name of your network interface?")

    interface = "Realtek PCIe GbE Family Controller"

    ip = "192.168.0.12"

    send_packets(ip, interface, NUM_PACKETS, DURATION)
