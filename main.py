import threading
import typing

import NetworkInterface

OUT_DIRECTION = "OUT"
IN_DIRECTION = "IN"


def main():
    print("Starting network capture...")
    # Create two threads: one for incoming and one for outgoing packets
    incoming_thread = threading.Thread(target=NetworkInterface.capture_packet(IN_DIRECTION))
    outgoing_thread = threading.Thread(target=NetworkInterface.capture_packet(OUT_DIRECTION))

    # Start both threads
    incoming_thread.start()
    outgoing_thread.start()

    # Join threads to ensure they run indefinitely
    incoming_thread.join()
    outgoing_thread.join()

    # Startsniffing packet each packet run thourgh the rule set and then storing them in the DB based on the rules
    # Manager


if __name__ == '__main__':
    main()
