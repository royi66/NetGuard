#!/usr/bin/sudo python
import threading
import typing

import NetworkInterface
from HandleDB import MongoDbClient
from PacketHandler import Packet
from datetime import datetime


OUT_DIRECTION = "OUT"
IN_DIRECTION = "IN"


def main():
    print("Starting network capture...")

    # Create two threads: one for incoming and one for outgoing packets
    incoming_thread = threading.Thread(target=NetworkInterface.capture_packet, args=[IN_DIRECTION])
    outgoing_thread = threading.Thread(target=NetworkInterface.capture_packet, args=[OUT_DIRECTION])

    # Start both threads
    incoming_thread.start()
    outgoing_thread.start()

    # Join threads to ensure they run indefinitely
    incoming_thread.join()
    outgoing_thread.join()


if __name__ == '__main__':
    main()
