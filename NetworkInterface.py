"""
Handles network interface - get output and input packets
"""
import typing
import threading

from HandleDB import MongoDbClient
from scapy.all import sniff, IP
from consts import ALL_PACKETS, PACKETS
import logging
from datetime import datetime
from PacketHandler import Packet
import HandleDB
from RuleManagement import RuleSet

# Configure logging to output network traffic to a file
logging.basicConfig(
    filename="network_traffic.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)


def log_packet(packet: Packet, direction: str) -> None:
    """
    Log the details of a captured packet.
    :param packet: The captured packet.
    :param direction: 'IN' for incoming, 'OUT' for outgoing.
    """
    new_packet = Packet(scapy_packet=packet, direction=direction)

    log_message = f"[{new_packet.direction}] Source: {new_packet.src_ip}, Destination: {new_packet.dest_ip}, Protocol: {new_packet.protocol}"
    logging.info(log_message)
    print(log_message)


def save_packet(packet: Packet) -> None:
    mongo_db_client = MongoDbClient()
    packet_data = packet.to_dict()
    print(packet_data)
    mongo_db_client.insert_to_db(ALL_PACKETS, PACKETS, packet_data)


def manage_sniffed_packet(packet: Packet, direction: str) -> None:
    new_packet = Packet(packet, direction)
    save_packet(new_packet)

    rule_set = RuleSet()
    rule_check_result = rule_set.check_packet(packet)
    #TODO: Action Based On Rule Check
    log_packet(packet, direction)


def capture_packet(direction: str):
    """Capture and log incoming packets."""
    try:
        sniff(filter="ip", prn=lambda pkt: manage_sniffed_packet(pkt, direction), store=0, iface="en0")
    except Exception as e:
        print(e)
