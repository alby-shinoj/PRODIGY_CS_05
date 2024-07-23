from scapy.all import sniff, IP, TCP

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto

        print(f"Source IP: {ip_src}")
        print(f"Destination IP: {ip_dst}")
        print(f"Protocol: {protocol}")

        if TCP in packet:
            tcp_payload = packet[TCP].payload
            print(f"Payload: {tcp_payload}")

# Sniff packets
sniff(prn=packet_callback, count=10)
