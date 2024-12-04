import unittest
from unittest.mock import MagicMock, patch
from scapy.all import IP  # Add this import for IP
from netguard.backend.packet import Packet
from netguard.backend.handle_network import manage_sniffed_packet, save_packet
from netguard.consts import DBNames, Collections
from netguard.backend.handle_db import MongoDbClient


class SimpleTestPacketCapture(unittest.TestCase):

    @patch('netguard.backend.handle_network.MongoDbClient')
    def test_manage_sniffed_packet(self, mock_mongo_client):
        # Mock a Scapy packet
        mock_packet = MagicMock()
        mock_packet[IP].src = '192.168.1.1'
        mock_packet[IP].dst = '192.168.1.2'
        mock_packet[IP].proto = 6  # TCP protocol
        mock_packet[IP].ttl = 64

        # Mock rule set that returns a matched rule ID
        mock_rule_set = MagicMock()
        mock_rule_set.check_packet.return_value = 1

        # Call manage_sniffed_packet
        manage_sniffed_packet(mock_packet, 'incoming', mock_rule_set)

        # Check that save_packet was called
        mock_mongo_client.return_value.insert_to_db.assert_called_once()

    def test_packet_initialization(self):
        # Simulate a raw packet initialization
        mock_packet = MagicMock()
        mock_packet[IP].src = '192.168.1.1'
        mock_packet[IP].dst = '192.168.1.2'
        mock_packet[IP].proto = 6  # TCP protocol

        # Create the Packet object
        packet = Packet(mock_packet, 'incoming')

        # Assert that the packet was initialized correctly
        self.assertEqual(packet.src_ip, '192.168.1.1')
        self.assertEqual(packet.dest_ip, '192.168.1.2')
        self.assertEqual(packet.protocol, 'TCP')

    @patch('netguard.backend.handle_network.MongoDbClient')
    def test_save_packet(self, mock_mongo_client):
        # Mock a packet to save
        mock_packet = MagicMock(spec=Packet)
        mock_packet.to_dict.return_value = {"src_ip": "192.168.1.1", "dst_ip": "192.168.1.2"}

        # Call the save_packet function
        save_packet(mock_packet, DBNames.NET_GUARD_DB, Collections.PACKETS)

        # Check that insert_to_db was called with the correct parameters
        mock_mongo_client.return_value.insert_to_db.assert_called_once_with(
            DBNames.NET_GUARD_DB, Collections.PACKETS, {"src_ip": "192.168.1.1", "dst_ip": "192.168.1.2"}
        )


if __name__ == '__main__':
    unittest.main()
