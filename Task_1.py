import socket
from scapy.all import *

def packet_handler(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        print(f"Source IP: {ip_src} -> Destination IP: {ip_dst} | Protocol: {protocol}")
    if packet.haslayer(TCP) or packet.haslayer(UDP):
        sport = packet.sport
        dport = packet.dport
        print(f"Source Port: {sport} -> Destination Port: {dport}")

def start_sniffer(packet_count=10):
    print(f"Starting network sniffer to capture {packet_count} packets...")
    sniff(filter="ip", prn=packet_handler, store=False, count=packet_count)
    print("Sniffing finished.")

if __name__ == "__main__":
    start_sniffer(packet_count=10)  
