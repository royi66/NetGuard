import threading

import NetworkInterface


def main():
    print("Starting network capture...")
    # Create two threads: one for incoming and one for outgoing packets
    incoming_thread = threading.Thread(target=NetworkInterface.capture_incoming)
    outgoing_thread = threading.Thread(target=NetworkInterface.capture_outgoing)

    # Start both threads
    incoming_thread.start()
    outgoing_thread.start()

    # Join threads to ensure they run indefinitely
    incoming_thread.join()
    outgoing_thread.join()


if __name__ == '__main__':
    main()