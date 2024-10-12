from pywebio.output import put_text, put_table, clear, put_buttons, put_image
from pywebio.input import input_group, input, actions
from pywebio import start_server
import matplotlib.pyplot as plt
from io import BytesIO

from HandleDB import MongoDbClient
from consts import DBNames, Collections


def get_rules():
    return [
        {"src_ip": "66.203.125.12", "dest_ip": "192.168.10.30", "protocol": "TCP", "action": "allow", "priority": 1},
        {"src_ip": "192.168.1.2", "dest_ip": "10.0.0.10", "protocol": "UDP", "action": "deny", "priority": 2},
        {"src_ip": "192.168.1.3", "dest_ip": "10.0.0.15", "protocol": "ICMP", "action": "allow", "priority": 3},
        {"src_ip": "192.168.1.4", "dest_ip": "10.0.0.20", "protocol": "TCP", "action": "deny", "priority": 4}
    ]


def manage_rules():
    clear()
    mongo_client = MongoDbClient()
    db = mongo_client.client[DBNames.NET_GUARD_DB]

    rules = get_rules()
    put_buttons(['Add New Rule'], onclick=[lambda: add_new_rule(db)])

    if rules:
        table_data = [['View Packets', 'Source IP', 'Destination IP', 'Protocol', 'Action', 'Priority', 'Edit/Delete']]
        for rule in rules:
            table_data.append([
                put_buttons(['View Packets'], onclick=[lambda r=rule: get_matching_packets(db, r)]),
                rule['src_ip'], rule['dest_ip'], rule['protocol'], rule['action'], rule['priority'],
                put_buttons(['Edit', 'Delete'], onclick=[lambda: edit_rule(rule), lambda: delete_rule(rule.get('_id'))])
            ])
        put_table(table_data)
    else:
        put_text("No rules found. Add some rules!")

    # Back button to return to the main menu
    put_buttons(['Back'], onclick=[main])


def add_new_rule(db):
    new_rule = input_group("Add New Rule", [
        input('Source IP', name='src_ip'),
        input('Destination IP', name='dest_ip'),
        input('Protocol (e.g., TCP, UDP, ICMP)', name='protocol'),
        input('Action (allow/deny)', name='action'),
        input('Priority', name='priority', type='number'),
    ])
    put_text(f"New rule added: {new_rule}")
    clear()
    manage_rules()  # Refresh the rules list


def get_matching_packets(db, rule):
    packets_collection = db[Collections.PACKETS]

    query = {
        "src_ip": rule["src_ip"],
        "dest_ip": rule["dest_ip"],
        "protocol": rule["protocol"]
    }
    matching_packets = list(packets_collection.find(query))

    if matching_packets:
        table_data = [["Source IP", "Destination IP", "Protocol", "Source Port", "Destination Port"]]
        for packet in matching_packets:
            table_data.append([
                packet["src_ip"],
                packet["dest_ip"],
                packet["protocol"],
                packet.get("src_port", "N/A"),
                packet.get("dest_port", "N/A")
            ])
        put_table(table_data)
    else:
        put_text("No packets match this rule.")


def edit_rule(rule):
    new_data = input_group("Edit Rule", [
        input('Source IP', name='src_ip', value=rule['src_ip']),
        input('Destination IP', name='dest_ip', value=rule['dest_ip']),
        input('Protocol', name='protocol', value=rule['protocol']),
        input('Action', name='action', value=rule['action']),
        input('Priority', name='priority', value=str(rule['priority'])),
    ])
    put_text("Rule updated!")


def delete_rule(rule_id):
    put_text("Rule deleted!")


def show_dashboard():
    clear()
    mongo_client = MongoDbClient()
    db = mongo_client.client[DBNames.NET_GUARD_DB]
    dashboard_collection = db[Collections.PACKETS]

    generate_protocol_pie_chart(dashboard_collection)
    in_and_out_packet_counter_dashboard(dashboard_collection)

    # Back button to return to the main menu
    put_buttons(['Back'], onclick=[main])


def generate_protocol_pie_chart(dashboard_collection):
    in_packets = list(dashboard_collection.find({"direction": "IN"}))
    protocol_counts = {}
    for packet in in_packets:
        protocol = packet.get('protocol', 'Unknown')
        protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1

    if protocol_counts:
        protocols = list(protocol_counts.keys())
        counts = list(protocol_counts.values())

        fig, ax = plt.subplots()
        ax.pie(counts, labels=protocols, autopct='%1.1f%%', startangle=90)
        ax.axis('equal')

        buf = BytesIO()
        plt.savefig(buf, format='png')
        buf.seek(0)
        put_image(buf.read())
    else:
        put_text("No 'IN' packets available for protocol distribution.")


def in_and_out_packet_counter_dashboard(dashboard_collection):
    pipeline = [{"$group": {"_id": "$direction", "count": {"$sum": 1}}}]
    results = list(dashboard_collection.aggregate(pipeline))

    table_data = [["Direction", "Packet Count"]]
    if results:
        for result in results:
            direction = result["_id"]
            count = result["count"]
            table_data.append([direction, count])
        put_table(table_data)
    else:
        put_text("No data available for packet directions.")


def main():
    clear()
    # Use actions to create a tab-like behavior
    tab = actions(label="Choose tab", buttons=["Manage Rules", "Dashboard"])

    if tab == "Manage Rules":
        manage_rules()
    elif tab == "Dashboard":
        show_dashboard()


if __name__ == '__main__':
    start_server(main, port=8080)
