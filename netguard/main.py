#!/usr/bin/sudo python
import threading

from backend.rule_management import RuleSet
from backend.handle_db import MongoDbClient
from backend.handle_network import capture_packet
from pywebio.platform.tornado_http import start_server
from pywebio import config
from ui_module import ui_main
from backend.logging_config import clear_log_file
from backend.anomaly_detection import AnomalyDetector
from consts import Directions

@config(theme="dark")
def main():
    clear_log_file()
    db_client = MongoDbClient()
    rule_set = RuleSet(db_client)
    anomaly_detector = AnomalyDetector(db_client)
    rule_set.print_all_rules()
    
    # Start packet capturing in separate threads
    incoming_thread = threading.Thread(target=capture_packet, args=[Directions.IN_DIRECTION, rule_set])
    outgoing_thread = threading.Thread(target=capture_packet, args=[Directions.OUT_DIRECTION, rule_set])
    anomaly_thread = threading.Thread(target=anomaly_detector.check_for_anomalies)
    # Start packet capture threads
    incoming_thread.start()
    outgoing_thread.start()
    anomaly_thread.start()

    # Start the UI server on the main thread (crucial for GUI to work on macOS)
    start_server(lambda: ui_main(rule_set, anomaly_detector), port=8088)

    # Join the packet capture threads (optional if they need to be waited for)
    incoming_thread.join()
    outgoing_thread.join()
    anomaly_thread.join()


if __name__ == '__main__':
    main()
