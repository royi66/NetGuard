import socket
from scapy.all import IP, TCP, UDP, ICMP

PROTOCOL_MAP = {
    1: "ICMP",   # Internet Control Message Protocol
    2: "IGMP",   # Internet Group Management Protocol
    6: "TCP",    # Transmission Control Protocol
    17: "UDP",   # User Datagram Protocol
    47: "GRE",   # Generic Routing Encapsulation
    50: "ESP",   # Encapsulating Security Payload
    51: "AH",    # Authentication Header
    89: "OSPF"   # Open Shortest Path First
    # Add more protocols as needed
}


class Packet:
    """Represents a network packet with source, destination, port, and protocol."""

    def __init__(self, scapy_packet):
        """
        Initialize the Packet object by extracting data from the scapy_packet.

        :param scapy_packet: A scapy packet object captured from the network.
        """
        self.scapy_packet = scapy_packet
        # Extract source IP from the scapy packet
        self.src_ip = scapy_packet[IP].src
        print("sssss ", self.src_ip)
        # Extract destination IP from the scapy packet
        self.dest_ip = scapy_packet[IP].dst
        # Extract protocol information
        self.protocol_num = scapy_packet[IP].proto
        self.protocol = PROTOCOL_MAP.get(self.protocol_num, f"Unknown protocol number {self.protocol_num}")
        # If the packet uses TCP, extract source and destination ports and set protocol to TCP
        if TCP in scapy_packet:
            self.src_port = scapy_packet[TCP].sport
            self.dest_port = scapy_packet[TCP].dport
        # If the packet uses UDP, extract source and destination ports and set protocol to UDP
        elif UDP in scapy_packet:
            self.src_port = scapy_packet[UDP].sport
            self.dest_port = scapy_packet[UDP].dport
        else:
            self.src_port = None  # No port available for non-TCP/UDP protocols
            self.dest_port = None
