"""
Handles network interface - get output and input packets
"""
import threading
from scapy.all import sniff, IP
import logging
from datetime import datetime
from PacketHandler import Packet

# Configure logging to output network traffic to a file
logging.basicConfig(
    filename="network_traffic.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)


def log_packet(packet, direction):
    """
    Log the details of a captured packet.
    :param packet: The captured packet.
    :param direction: 'IN' for incoming, 'OUT' for outgoing.
    """
    new_packet = Packet(packet)

    log_message = f"[{direction}] Source: {new_packet.src_ip}, Destination: {new_packet.dest_ip}, Protocol: {new_packet.protocol}"
    logging.info(log_message)
    print(log_message)


def capture_incoming():
    """Capture and log incoming packets."""
    sniff(filter="ip", prn=lambda pkt: log_packet(pkt, "IN"), store=0, iface="en0")


def capture_outgoing():
    """Capture and log outgoing packets."""
    sniff(filter="ip", prn=lambda pkt: log_packet(pkt, "OUT"), store=0, iface="en0")


def main():
    print("Starting network capture...")
    # Create two threads: one for incoming and one for outgoing packets
    incoming_thread = threading.Thread(target=capture_incoming)
    outgoing_thread = threading.Thread(target=capture_outgoing)

    # Start both threads
    incoming_thread.start()
    outgoing_thread.start()

    # Join threads to ensure they run indefinitely
    incoming_thread.join()
    outgoing_thread.join()




if __name__ == '__main__':
    main()
