"""
Handles network interface - get output and input packets
"""
import typing
import threading
from scapy.all import sniff, IP
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
    new_packet = Packet(packet)

    log_message = f"[{direction}] Source: {new_packet.src_ip}, Destination: {new_packet.dest_ip}, Protocol: {new_packet.protocol}"
    logging.info(log_message)
    print(log_message)


def manage_sniffed_packet(packet: Packet, direction: str) -> None:
    rule_set = RuleSet()
    rule_check_result = rule_set.check_packet(packet)
    #TODO: Action Based On Rule Check
    log_packet(packet, direction)


def capture_packet(direction: str):
    """Capture and log incoming packets."""
    sniff(filter="ip", prn=lambda pkt: manage_sniffed_packet(pkt, direction), store=0, iface="en0")
