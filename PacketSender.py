"""
TO-DO:

- Create Packet sender that can send packets
- Ability to replicate DDOS to show that firewall can block it
- Ability to simulate signature-based attack
"""

import sys
import time
from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.l2 import Ether


# Sends packets to target IP using selected attack mode
def send_packets(target_ip, interface, num_packets, duration, mode="ddos"):
    if mode == "signature":
        # Packet with suspicious payload to trigger signature detection
        packet = Ether() / IP(dst=target_ip) / TCP(dport=80) / Raw(load="cmd.exe")
    else:
        # Regular TCP packet for DDoS simulation
        packet = Ether() / IP(dst=target_ip) / TCP()

    end_time = time.time() + duration
    packet_count = 0

    while time.time() < end_time and packet_count < num_packets:
        sendp(packet, iface=interface, verbose=False)
        packet_count += 1

if __name__ == "__main__":

    # Default values for testing
    packet_number = 1000
    duration = 5

    ip = input("Please enter the target IP: ")
    interface = input("Please enter the target interface: ")

    # Select attack type
    print("Select attack type:")
    print("1. DDoS Simulation")
    print("2. Signature-Based Attack")
    choice = input("Enter 1 or 2: ")

    if choice == "2":
        attack_mode = "signature"
    else:
        attack_mode = "ddos"

    send_packets(ip, interface, packet_number, duration, mode=attack_mode)
