import unittest
from scapy.all import IP, TCP, UDP, ICMP, Raw
from netguard.backend.packet import Packet  # Import the Packet class


class TestPacket(unittest.TestCase):
    def test_packet_initialization_tcp(self):
        # Create a mock TCP packet using Scapy
        scapy_packet = IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=12345, dport=80)

        # Create Packet object from scapy packet
        packet = Packet(scapy_packet, direction="in")

        # Assertions
        self.assertEqual(packet.src_ip, "192.168.1.1")
        self.assertEqual(packet.dest_ip, "192.168.1.2")
        self.assertEqual(packet.protocol, "TCP")
        self.assertEqual(packet.src_port, 12345)
        self.assertEqual(packet.dest_port, 80)
        self.assertIsNone(packet.icmp_type)  # Should be None for TCP packet
        self.assertIsNone(packet.icmp_code)  # Should be None for TCP packet
        self.assertEqual(packet.ttl, scapy_packet[IP].ttl)

    def test_packet_initialization_icmp(self):
        # Create a mock ICMP packet using Scapy
        scapy_packet = IP(src="192.168.1.1", dst="192.168.1.2") / ICMP(type=8, code=0)

        # Create Packet object from scapy packet
        packet = Packet(scapy_packet, direction="out")

        # Assertions
        self.assertEqual(packet.src_ip, "192.168.1.1")
        self.assertEqual(packet.dest_ip, "192.168.1.2")
        self.assertEqual(packet.protocol, "ICMP")
        self.assertIsNone(packet.src_port)  # ICMP doesn't have ports
        self.assertIsNone(packet.dest_port)  # ICMP doesn't have ports
        self.assertEqual(packet.icmp_type, 8)
        self.assertEqual(packet.icmp_code, 0)
        self.assertEqual(packet.ttl, scapy_packet[IP].ttl)

    def test_packet_with_payload(self):
        # Create a mock packet with a Raw payload
        scapy_packet = IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=12345, dport=80) / Raw(load="Test Payload")

        # Create Packet object from scapy packet
        packet = Packet(scapy_packet, direction="in")

        # Assertions
        self.assertEqual(packet.payload, "Test Payload")
        self.assertEqual(packet.length, len(scapy_packet))  # Length of the packet should match
        self.assertEqual(packet.protocol, "TCP")  # Protocol should still be TCP

    def test_packet_fragmentation(self):
        # Create a fragmented IP packet (to test fragmentation)
        scapy_packet = IP(src="192.168.1.1", dst="192.168.1.2", frag=1, flags="MF") / TCP(sport=12345, dport=80)

        # Create Packet object from scapy packet
        packet = Packet(scapy_packet, direction="out")

        # Assertions
        self.assertEqual(packet.fragment_offset, 1)
        self.assertEqual(packet.more_fragments, "MF")  # Scapy sets MF for more fragments

    def test_unknown_protocol(self):
        # Create a mock packet with an unknown protocol
        scapy_packet = IP(src="192.168.1.1", dst="192.168.1.2", proto=99)  # Protocol 99 doesn't exist in PROTOCOL_MAP

        # Create Packet object from scapy packet
        packet = Packet(scapy_packet, direction="out")

        # Assertions
        self.assertEqual(packet.protocol, "Unknown protocol number 99")


if __name__ == "__main__":
    unittest.main()
