
import os
import sys
import time
from collections import defaultdict
from scapy.all import sniff
from scapy.layers.inet import IP

# Firewall Project

"""
 To-Do

- Detecting and blocking of IP packets being received (Using Scapy.sniff?)
- Whitelist
- Blacklist
- DDOS Protection

"""

def firewall(packet):
    ip = packet[IP].src #Grabs IP from packet


if __name__ == "__main__":

    # Ability to add IPs to blacklist's manually
    add_ip = 'b'
    while add_ip != 'y' and add_ip != 'n':
        add_ip = input("Would you like to enter or remove IP's to blacklist manually? (Y/N) ")
        add_ip = add_ip.lower()

    if add_ip == "y":
        choice = 0
        while choice != 1 and choice != 2:
            choice = input("\nWhich would you like to do?\n1. Add\n2. Remove\n")
            choice = int(choice)

        new_ip = input("\nPlease enter IP: ")

        if choice == 1:
            blist = open('blacklist.txt', 'a')
            blist.write(new_ip)
            blist.write('\n')
            blist.close()

        if choice == 2:
            # We can decide if we want this functionality or not, doesn't work yet
            blist = open('blacklist.txt', 'a')
            blist.close()

    print("Detecting IP's...")
    sniff(filter="ip", prn=firewall) #Grabs IP and sends it's packet to firewall function