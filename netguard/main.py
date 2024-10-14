#!/usr/bin/sudo python
import threading

import network_interface
from rule_management import RuleSet
from handle_db import MongoDbClient
from pywebio.platform.tornado_http import start_server
from pywebio import config
from ui_module import ui_main


OUT_DIRECTION = "OUT"
IN_DIRECTION = "IN"


@config(theme="dark")
def main():
    db_client = MongoDbClient()
    rule_set = RuleSet(db_client)

    # Add example rules
    rule_set.add_rule(src_ip='192.168.1.1', action='allow')
    rule_set.add_rule(dest_ip='10.0.0.2', action='block')

    # Print all rules
    rule_set.print_all_rules()

    # Clear all rules
    # rule_set.clear_all_rules()

    incoming_thread = threading.Thread(target=network_interface.capture_packet, args=[IN_DIRECTION, rule_set])
    outgoing_thread = threading.Thread(target=network_interface.capture_packet, args=[OUT_DIRECTION, rule_set])

    ui_thread = threading.Thread(target=lambda: start_server(ui_main, port=8080))

    incoming_thread.start()
    outgoing_thread.start()
    ui_thread.start()

    # Join threads to ensure they run indefinitely
    incoming_thread.join()
    outgoing_thread.join()
    ui_thread.join()


if __name__ == '__main__':
    main()
