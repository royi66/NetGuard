"""
Handles network interface - get output and input packets
"""
import threading
from scapy.all import sniff, IP
import logging
from PacketHandler import Packet
import HandleDB

# Configure logging to output network traffic to a file
logging.basicConfig(
    filename="network_traffic.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)


def process_packet(packet, direction):
    """Process and save packet data."""
    new_packet = Packet(packet, direction)
    packet_data = new_packet.to_dict()  # Convert packet object to dictionary
    print(f"[{direction}] Source: {new_packet.src_ip}, Destination: {new_packet.dest_ip}, Protocol: {new_packet.protocol}")
    HandleDB.save_packet_to_db(packet_data)  # Save to MongoDB


def capture_incoming():
    """Capture and log incoming packets."""
    sniff(filter="ip", prn=lambda pkt: process_packet(pkt, "IN"), store=0, iface="en0")


def capture_outgoing():
    """Capture and log outgoing packets."""
    sniff(filter="ip", prn=lambda pkt: process_packet(pkt, "OUT"), store=0, iface="en0")


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
