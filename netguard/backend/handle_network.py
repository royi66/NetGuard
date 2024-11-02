"""
Handles network interface - get output and input packets
"""
from backend.handle_db import MongoDbClient
from scapy.all import sniff
from consts import DBNames, Collections
from backend.packet import Packet
from scapy.config import conf
from backend.logging_config import logger

conf.debug_dissector = 2


def capture_packet(direction: str, rule_set) -> None:
    """Capture and log incoming packets."""
    try:
        sniff(filter="ip", prn=lambda pkt: manage_sniffed_packet(pkt, direction, rule_set), store=0, iface="en0")
    except Exception as e:
        logger.error(e)


def manage_sniffed_packet(packet, direction, rule_set):
    try:
        new_packet = Packet(packet, direction)
        matched_rule_id = rule_set.check_packet(packet)
        if matched_rule_id >= 0:
            logger.info(f"Matched rule: {matched_rule_id}")
            new_packet.matched_rule_id = matched_rule_id
        save_packet(new_packet, DBNames.NET_GUARD_DB, Collections.PACKETS)
    except Exception as e:
        logger.error(f"Error processing packet: {packet.show()} with error {e}")


def save_packet(packet: Packet, db_name: str, collection_name: str) -> None:
    mongo_db_client = MongoDbClient()
    packet_data = packet.to_dict()
    mongo_db_client.insert_to_db(db_name, collection_name, packet_data)
    mongo_db_client.close_connection()

