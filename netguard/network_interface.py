"""
Handles network interface - get output and input packets
"""

from handle_db import MongoDbClient
from scapy.all import sniff
from consts import DBNames, Collections
import logging
from packet_handler import Packet
from rule_management import RuleSet

# Configure logging to output network traffic to a file
logging.basicConfig(
    filename="log/network_traffic.log",
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


def save_packet(packet: Packet, db_name: str, collection_name: str) -> None:
    mongo_db_client = MongoDbClient()
    packet_data = packet.to_dict()
    mongo_db_client.insert_to_db(db_name, collection_name, packet_data)


def manage_sniffed_packet(packet: Packet, direction: str, rule_set: RuleSet) -> None:
    new_packet = Packet(packet, direction)
    matched_rule_id = rule_set.check_packet(packet)
    if matched_rule_id:
        packet.matched_rule_id = matched_rule_id
    save_packet(new_packet, DBNames.NET_GUARD_DB, Collections.PACKETS)

    # TODO: Action Based On Rule Check
    # log_packet(packet, direction)


def capture_packet(direction: str, rule_set) -> None:
    """Capture and log incoming packets."""
    try:
        sniff(filter="ip", prn=lambda pkt: manage_sniffed_packet(pkt, direction, rule_set), store=0, iface="en0")
    except Exception as e:
        print(e)
