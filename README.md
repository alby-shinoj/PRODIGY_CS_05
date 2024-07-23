# PRODIGY_CS_05
Packet Sniffer

Step-by-Step Guide
Install Scapy:
pip install scapy


Explanation:
Importing Scapy: The from scapy.all import sniff, IP, TCP line imports the necessary components from Scapy.
Callback Function: The packet_callback function processes each packet. It extracts and prints the source IP, destination IP, protocol, and TCP payload if present.
Sniffing Packets: The sniff function captures packets and calls the packet_callback function for each packet. The count=10 parameter limits the capture to 10 packets.
