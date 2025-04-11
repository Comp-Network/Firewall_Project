
import os
import sys
import time
from scapy.all import *
from scapy.layers.inet import IP
import ctypes
import subprocess

# Firewall Project

"""
 To-Do

- Detecting and blocking of IP packets being received (Using Scapy.sniff?)
- Whitelist 
- Blacklist
- DDOS Protection

"""

# These don't work yet!! Incorrect rule being sent to system?
def ip_unblock(ip):
    os.system(f'netsh advfirewall firewall delete rule name="BlockIP-{ip}"')
    print(ip, " is unblocked!")


def ip_block(ip):
    # Sends a command to block IP on Windows Computer
    message = f'netsh advfirewall firewall add rule name="BlockIP-{ip}" dir=in interface=any action=block remoteip={ip}'
    os.system(message)
    print(ip, " is blocked!")


# Completely Unfinished, uhhhhh nothing  works yet
def firewall(current_packet):
    print("Made it here!")

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
                blist.write(ip)
                blist.write('\n')
                blist.close()

                blist_ips.append(ip)
                ip_block(ip)

        # Now that DDOS is checked, reset for next time
        pack_count.clear()
        t_start[0] = time.time()

def settings():

    # Default max packets, initialized here to be returned
    new_max_packets = 50

    # Create while loop to stay on settings
    setting_leave = False
    while not setting_leave:

        settings_choice = 0
        while 1 > settings_choice or settings_choice > 4:
            settings_choice = input("What would you like to do?\n1. Add to Blacklist\n2. Add to Whitelist\n3. Adjust DDOS Sensitivity\n4. Exit\n")
            settings_choice = int(settings_choice)

        # Add to blacklist
        if settings_choice == 1:
            new_ip = input("\nPlease enter IP: ")

            blist = open('blacklist.txt', 'a')
            blist.write(new_ip)
            blist.write('\n')
            blist.close()

            print("IP Added!")

        # Add to whitelist
        if settings_choice == 2:
            new_ip = input("\nPlease enter IP: ")

            wlist = open('whitelist.txt', 'a')
            wlist.write(new_ip)
            wlist.write('\n')
            wlist.close()

            print("IP Added!")

        # Number to determine how sensitive the firewall will be to DDOS Attacks
        if settings_choice == 3:
            value = input("\nHow sensitive would you like the firewall to be when preventing DDOS Attacks?\nThe higher the more sensitive.\nPlease enter 0-100 (If unsure, do 50)\n")
            new_max_packets = int(value)

        if settings_choice == 4:
            setting_leave = True


    return new_max_packets


if __name__ == "__main__":
    #Checks if program is running with needed admin privileges
    if not ctypes.windll.shell32.IsUserAnAdmin():
        print("Admin Privileges required to run program!")
        sys.exit(1)

    # Default max_packets
    max_packets = 50

    # While loop to ask what to do in program
    leave = False
    while not leave:

        choice = 0
        while choice != 1 and choice != 2 and choice != 3:
            choice = input("What would you like to do?\n1. Start Firewall\n2. Go to settings\n3. Exit\n")
            choice = int(choice)

        if choice == 1:
            leave = True

        if choice == 2:
            max_packets = settings()

        if choice == 3:
            sys.exit(0)

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

    print(max_packets)

    # Grabs IP and sends it's packet to firewall function
    print("Detecting IP's...")
    sniff(filter="ip", prn=firewall)