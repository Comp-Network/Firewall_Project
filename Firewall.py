
import os
import sys
import time
from collections import defaultdict
from scapy.all import *
from scapy.layers.inet import IP
import ctypes

# Firewall Project

"""
 To-Do

- Detecting and blocking of IP packets being received (Using Scapy.sniff?)
- Whitelist 
- Blacklist
- DDOS Protection

"""

# These don't work yet!! Incorrect rule being sent to system?
def ip_block(ip):
    print("Made it here!")
    os.system(f'netsh advfirewall firewall delete rule name="BlockIP-{ip}"')
    print(ip, " is blocked!")


def ip_unblock(ip):
    # Sends a command to block IP on Windows Computer
    os.system(f'netsh advfirewall firewall add rule name="BlockIP-{ip}" dir=out action=block remoteip={ip}')
    print(ip, " is unblocked!")


# Completely Unfinished
def firewall(current_packet):
    # Grabs IP from packet
    ip = current_packet[IP].src


    # Returns if IP is in whitelist
    if ip in wlist_ips:
        return

    # Blocks IP if it is in blocklist
    if ip in blist_ips:
       ip_block(ip)



if __name__ == "__main__":
    #Checks if program is running with needed admin privileges
    if not ctypes.windll.shell32.IsUserAnAdmin():
        print("Admin Privileges required to run program!")
        sys.exit(1)

    # Ability to add IPs to blacklist and whitelist manually
    add_ip = 'b'
    while add_ip != 'y' and add_ip != 'n':
        add_ip = input("Would you like to enter IP's to blacklist or whitelist manually? (Y/N) ")
        add_ip = add_ip.lower()

    if add_ip == "y":
        choice = 0
        while choice != 1 and choice != 2:
            choice = input("Which would you like to add to?\n1. Whitelist\n2. Blacklist\n")
            choice = int(choice)

        new_ip = input("\nPlease enter IP: ")

        if choice == 1:
            wlist = open('whitelist.txt', 'a')
            wlist.write(new_ip)
            wlist.write('\n')
            wlist.close()

        elif choice == 2:
            blist = open('blacklist.txt', 'a')
            blist.write(new_ip)
            blist.write('\n')
            blist.close()

        print("IP Added!")

    # Create set for whitelist and blacklist
    wlist = open('whitelist.txt', 'r')
    wlist_ips = wlist.read().splitlines()

    blist = open('blacklist.txt', 'r')
    blist_ips = blist.read().splitlines()

    # Grabs IP and sends it's packet to firewall function
    print("Detecting IP's...")
    sniff(filter="ip", prn=firewall)