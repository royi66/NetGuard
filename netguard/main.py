#!/usr/bin/sudo python
import threading

import handle_network
from rule_management import RuleSet
from handle_db import MongoDbClient
from pywebio.platform.tornado_http import start_server
from pywebio import config
from Frontened.ui_module import main as ui_main


OUT_DIRECTION = "OUT"
IN_DIRECTION = "IN"


@config(theme="dark")
def main():
    from scapy.all import get_if_list
    print(get_if_list())  # Print available interfaces
    db_client = MongoDbClient()
    rule_set = RuleSet(db_client)

    # Clear all rules
    rule_set.clear_all_rules()
    rule_set.add_rule(src_ip='10.0.0.5', alert=True)
    rule_set.add_rule(dest_ip='10.0.0.255', alert=True)
    # Add example rules
    rule_set.print_all_rules()
    
    # Start packet capturing in separate threads
    incoming_thread = threading.Thread(target=handle_network.capture_packet, args=[IN_DIRECTION, rule_set])
    outgoing_thread = threading.Thread(target=handle_network.capture_packet, args=[OUT_DIRECTION, rule_set])

    # Start packet capture threads
    incoming_thread.start()
    outgoing_thread.start()

    # Start the UI server on the main thread (crucial for GUI to work on macOS)
    start_server(lambda: ui_main(rule_set), port=8088)

    # Join the packet capture threads (optional if they need to be waited for)
    incoming_thread.join()
    outgoing_thread.join()


if __name__ == '__main__':
    main()
