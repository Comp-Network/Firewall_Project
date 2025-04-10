
import os
import sys
import time
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
    print(ip, " is unblocked!")


def ip_unblock(ip):
    # Sends a command to block IP on Windows Computer
    message = f'netsh advfirewall firewall add rule name="BlockIP-{ip}" dir=in interface=any action=block remoteip={ip}'
    os.system(message)
    print(ip, " is blocked!")


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

    # Number of packets counter
    pack_count[ip] += 1

    # Interval between start time and current time
    t_interval = time.time() - t_start[0]

    # Checks if 1 second has passed, if so start checking for DDOS
    if t_interval > 1:
        for ip, count in pack_count.items():
            rate = count / t_interval

            if rate > max_packets:
                print("High packet rate detected! Source: ", ip)

            if ip not in blist_ips:
                blist = open('blacklist.txt', 'a')
                blist.write(new_ip)
                blist.write('\n')
                blist.close()

                blist_ips.append(ip)
                ip_block(ip)


        pack_count.clear()
        t_start[0] = time.time()




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

    # Create sets for whitelist and blacklist
    wlist = open('whitelist.txt', 'r')
    wlist_ips = wlist.read().splitlines()
    wlist.close()

    blist = open('blacklist.txt', 'r')
    blist_ips = blist.read().splitlines()
    blist.close()

    #Dictonary to count number of packets from IP
    pack_count = {}

    # Starting time to be used in DDOS tracker
    t_start = [time.time()]

    # Number to determine how sensitive the firewall will be to DDOS
    max_packets = input("How sensitive would you like the firewall to be to DDOS? Please enter 0-100 (If unsure, do 50)")

    # Grabs IP and sends it's packet to firewall function
    print("Detecting IP's...")
    sniff(filter="ip", prn=firewall)