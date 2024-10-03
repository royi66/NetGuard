import socket
from scapy.all import IP, TCP, UDP, ICMP, Raw
import HandleDB


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

    def __init__(self, scapy_packet, direction):
        """
        Initialize the Packet object by extracting data from the scapy_packet.

        :param scapy_packet: A scapy packet object captured from the network.
        """
        self.direction = direction
        self.scapy_packet = scapy_packet

        # Extract source IP from the scapy packet
        self.src_ip = scapy_packet[IP].src

        # Extract destination IP from the scapy packet
        self.dest_ip = scapy_packet[IP].dst

        # Extract protocol information
        self.protocol_num = scapy_packet[IP].proto
        self.protocol = PROTOCOL_MAP.get(self.protocol_num, f"Unknown protocol number {self.protocol_num}")

        self.ttl = scapy_packet[IP].ttl
        self.length = len(scapy_packet)

        """
        The IP layer can fragment packets. Monitoring fragmentation is useful to detect fragmentation attacks, 
        where attackers fragment packets to evade firewall rules or IDS systems
        """
        self.fragment_offset = scapy_packet[IP].frag
        self.more_fragments = scapy_packet[IP].flags & 0x1  # Check MF flag

        # If the packet uses TCP, extract source and destination ports and set protocol to TCP
        if TCP in scapy_packet:
            self.src_port = scapy_packet[TCP].sport
            self.dest_port = scapy_packet[TCP].dport
            self.tcp_flags = scapy_packet[TCP].flags
            self.checksum = scapy_packet[TCP].chksum

        # If the packet uses UDP, extract source and destination ports and set protocol to UDP
        elif UDP in scapy_packet:
            self.src_port = scapy_packet[UDP].sport
            self.dest_port = scapy_packet[UDP].dport
        else:
            self.src_port = None  # No port available for non-TCP/UDP protocols
            self.dest_port = None

        """
        Why it’s important: If you're scanning ICMP packets, such as those used in ping requests, 
        the type and code fields can provide information about the nature of the ICMP message. For example, 
        ICMP Type 8 is a ping request, and Type 0 is a ping reply.
        Example: A firewall scanner could detect ping floods (DoS attack) by monitoring high volumes of ICMP requests.
        """
        if scapy_packet.haslayer(ICMP):
            self.icmp_type = scapy_packet[ICMP].type
            self.icmp_code = scapy_packet[ICMP].code

        # Extract the payload if it exists
        if Raw in scapy_packet:
            self.payload = scapy_packet[Raw].load  # Raw payload data
        else:
            self.payload = None

    def to_dict(self):
        """
        Convert the Packet object into a dictionary dynamically by using the __dict__ attribute.
        :return: A dictionary representation of the Packet object.
        """
        return {k: v for k, v in self.__dict__.items() if v is not None}  # Only include non-None fields
