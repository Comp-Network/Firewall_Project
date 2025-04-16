Welcome to the firewall project, created by Noah Vining, Gurjit Singh, and Kristyan Popov

This program acts to block incoming network packets based on specific criteria.

To run the program, Python3 must be used as the intepreter and the scapy library must be installed. 

In the main firewall program, there are two options, 'run the firewall' and 'settings'.

	Running the firewall starts up packet detecting and blocking, and will do so until the program is closed.

	Settings lists a couple options on altering criteria for the firewall, such as adding to the black and white lists manually, and altering the sensitivity of the DDOS prevention. 

To run the tester, you must enter a target IP and network interface for the tester to correctly push the packets. 
	
	You may also change the number of packets sent and the duration by which they are sent in the code itself if you would like.  