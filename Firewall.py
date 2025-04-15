from scapy.all import *
from scapy.layers.inet import IP
import ctypes
import os
import time
import re

# Firewall Project

"""
 To-Do

- Detecting and blocking of IP packets being received (Using Scapy.sniff?)
- Whitelist 
- Blacklist
- DDOS Protection
- Signature-Based Detection (added)
- Subnet-Based Blocking (added)
"""

# Signature patterns for signature-based detection (simulating antigen recognition)
signature_patterns = [
    r"GET\s+/scripts/root\.exe",         # Nimda worm
    r"cmd\.exe",                         # Command execution
    r"powershell",                       # Powershell access
    r"/bin/bash",                        # Linux shell
    r"wget\s+http",                      # Attempt to fetch file
    r"net\s+user",                       # User enumeration
    r"Content-Disposition:\s+form-data"  # File upload
]

# Use this to wipe the blocklist in case of emergency
def clear_blocklist(list_ips):
    for ip in list_ips:
        ip_unblock(ip)

# These don't work yet!! Incorrect rule being sent to system?
def ip_unblock(ip):
    message = f'netsh advfirewall firewall delete rule name="BlockIP-{ip}"'
    os.system(message)
    print(ip, " is unblocked!")

def ip_block(ip):
    # Sends a command to block IP on Windows Computer
    message = f'netsh advfirewall firewall add rule name="BlockIP-{ip}" dir=in interface=any action=block remoteip={ip}'
    os.system(message)

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
       print(ip, " is blocked!")
       return

    # Signature-based detection
    if current_packet.haslayer(Raw):
        payload = str(current_packet[Raw].load)

        for pattern in signature_patterns:
            if re.search(pattern, payload, re.IGNORECASE):
                print(f"[SIGNATURE DETECTED] Suspicious content from {ip}: matched {pattern}")

                if ip not in blist_ips:
                    with open('blacklist.txt', 'a') as blist:
                        blist.write(ip + '\n')
                    blist_ips.append(ip)
                    ip_block(ip)
                    print(f"[BLOCKED] {ip} has been blacklisted due to signature match.")

                    # Subnet blocking based on detected malicious IP
                    try:
                        subnet_prefix = ".".join(ip.split(".")[:3])
                        last_octet = int(ip.split(".")[3])
                        for offset in range(-2, 3):
                            neighbor_octet = last_octet + offset
                            if 1 <= neighbor_octet <= 254:
                                neighbor_ip = f"{subnet_prefix}.{neighbor_octet}"
                                if neighbor_ip != ip and neighbor_ip not in blist_ips:
                                    with open('blacklist.txt', 'a') as blist:
                                        blist.write(neighbor_ip + '\n')
                                    blist_ips.append(neighbor_ip)
                                    ip_block(neighbor_ip)
                                    print(f"[SUBNET BLOCK] {neighbor_ip} blocked (related to {ip})")
                    except Exception as e:
                        print("Subnet block error:", e)

                return

    # Number of packets counter
    if ip in pack_count:
        pack_count[ip] += 1

    else:
        pack_count[ip] = 1

    # Interval between start time and current time
    real_time = time.time()
    t_interval = real_time - t_start[0]

    # Checks if 1 second has passed, if so start checking for DDOS
    if t_interval > 1:

        for ip, count in pack_count.items():
            rate = count / t_interval

            if rate > max_rate:
                print("High packet rate detected! Source: ", ip)

                if ip not in blist_ips:
                    blist = open('blacklist.txt', 'a')
                    blist.write(ip)
                    blist.write('\n')
                    blist.close()

                    blist_ips.append(ip)
                    ip_block(ip)
                    print(ip, " is now blocked!")

        # Now that DDOS is checked, reset for next time
        pack_count.clear()
        t_start[0] = real_time

def settings():

    # Default max packets, initialized here to be returned
    new_max_rate = 50

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
            new_max_rate = int(value)

        if settings_choice == 4:
            setting_leave = True

    return new_max_rate


if __name__ == "__main__":
    #Checks if program is running with needed admin privileges
    if not ctypes.windll.shell32.IsUserAnAdmin():
        print("Admin Privileges required to run program!")
        sys.exit(1)

    # Default max_packets
    max_rate = 50

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
            max_rate = settings()

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

    # Grabs IP and sends it's packet to firewall function
    print("Detecting IP's...")
    sniff(filter="ip", prn=firewall)
