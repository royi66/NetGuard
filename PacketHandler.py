import socket
from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP, UDP


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
        # Extract destination IP from the scapy packet
        self.dest_ip = scapy_packet[IP].dst
        # Extract protocol information (TCP or UDP)
        self.protocol = scapy_packet.proto
        # If the packet uses TCP, extract source and destination ports and set protocol to TCP
        if TCP in scapy_packet:
            self.src_port = scapy_packet[TCP].sport
            self.dest_port = scapy_packet[TCP].dport
            self.protocol = "TCP"
        # If the packet uses UDP, extract source and destination ports and set protocol to UDP
        elif UDP in scapy_packet:
            self.src_port = scapy_packet[UDP].sport
            self.dest_port = scapy_packet[UDP].dport
            self.protocol = "UDP"