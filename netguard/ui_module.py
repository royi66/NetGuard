from pywebio import *
from pywebio.output import *
from pywebio.input import *
from pymongo import MongoClient
import os
from handle_db import MongoDbClient
from consts import DBNames, Collections, HOURS_BACK, ICON_URL
from datetime import timedelta, datetime
from rule_management import Rule, RuleSet
import matplotlib.pyplot as plt
from io import BytesIO
import matplotlib
matplotlib.use('Agg')  # Use non-GUI backend
from matplotlib.backends.backend_agg import FigureCanvasAgg as FigureCanvas
from dash import Dash, dcc, html
import plotly.graph_objs as go
from threading import Thread
from dashboard import run_dash_app

app = Dash(__name__)
mongo_client = MongoDbClient()
db = mongo_client.client[DBNames.NET_GUARD_DB]
images_dir = os.path.join(os.path.dirname(__file__), '../Images')


def get_recent_packets():
    packets_collection = db[Collections.PACKETS]
    one_hour_ago = datetime.now() - timedelta(hours=HOURS_BACK)
    query = {"insertion_time": {"$gte": one_hour_ago}}
    matching_packets = list(packets_collection.find(query))
    return [
        {
            "_id": packet.get("_id", None),
            "src_ip": packet.get("src_ip", ""),
            "dest_ip": packet.get("dest_ip", ""),
            "src_port": packet.get("src_port", ""),
            "dest_port": packet.get("dest_port", ""),
            "protocol": packet.get("protocol", ""),
            "action": packet.get("action", "")
        }
        for packet in matching_packets
    ]


def put_packet_search(packet_id):
    """Retrieve and display the packet details based on src_ip or packet_id."""
    popup("Packet Info", [put_scope("popup_content")], PopupSize.LARGE)
    with use_scope("popup_content"):
        # Query MongoDB for the packet by src_ip
        print(packet_id)
        packet = mongo_client.get_data_by_field(DBNames.NET_GUARD_DB, Collections.PACKETS, "_id", packet_id)
        print("find", packet)

        if packet:
            put_table(
                tdata=[
                    ["_id", str(packet.get("_id", ""))],
                    ["Direction", packet.get("direction", "")],
                    ["Source IP", packet.get("src_ip", "")],
                    ["Destination IP", packet.get("dest_ip", "")],
                    ["Protocol", packet.get("protocol", "")],
                    ["Protocol Number", packet.get("protocol_num", "")],
                    ["TTL", packet.get("ttl", "")],
                    ["Length", packet.get("length", "")],
                    ["Source Port", packet.get("src_port", "")],
                    ["Destination Port", packet.get("dest_port", "")],
                    ["Matched Rule ID", packet.get("matched_rule_id", "")],
                    ["Fragment Offset", packet.get("fragment_offset", "")],
                    ["More Fragments", packet.get("more_fragments", "")],
                    ["Payload", packet.get("payload", "")],
                    ["Insertion Time", str(packet.get("insertion_time", ""))]
                ],
                header=["Field", "Value"]
            )
        else:
            put_markdown(f"**Packet not found**").style("color: red")



@use_scope("dashboard", clear=True)
def put_blocks():
    put_markdown("## Network Packets")
    put_scope("search")
    put_scope("results")
    put_scope("latest")

    with use_scope("search"):
        # Dropdown for choosing the search field
        pin.put_select(name='search_field', label='Select Field to Search', options=[
            ('Source IP', 'src_ip'),
            ('Destination IP', 'dest_ip'),
            ('Direction', 'direction'),
        ], value='src_ip')  # Default value is Source IP
        selected_field = pin.pin['search_field']

        # Input for search query
        pin.put_input(name='search_value', placeholder="Enter value for the selected field")

        put_button(
            "Search",
            onclick=lambda: put_packet_search_results(
                field=pin.pin["search_field"], value=pin.pin["search_value"]
            ),
            outline=True,
        )

    put_latest_packets()


@use_scope("results", clear=True)
def put_packet_search_results(field, value):
    try:
        print({field: value})
        packets = mongo_client.get_data_by_field(DBNames.NET_GUARD_DB, Collections.PACKETS, field, value)
        print("packets", packets)

        if packets:
            put_markdown(f"### Packets matching {field}: {value}")
            for packet in packets:
                put_table(
                    tdata=[
                        ["Source IP", packet.get("src_ip", "")],
                        ["Destination IP", packet.get("dest_ip", "")],
                        ["Protocol", packet.get("protocol", "")],
                        ["Action", packet.get("action", "")],
                        ["TTL", packet.get("ttl", "")],
                        ["Length", packet.get("length", "")],
                        ["Payload", packet.get("payload", "")],
                        ["Insertion Time", str(packet.get("insertion_time", ""))]
                    ],
                    header=["Field", "Value"]
                )
                put_markdown("---")  # Separator between packet entries
        else:
            put_text("Packet not found.")
    except Exception as e:
        print(f"Error: {e}")


@use_scope("latest")
def put_latest_packets():
    latest_packets = get_recent_packets()  # Replace with real scanning function
    print("latest_packets", latest_packets)
    packets = []
    for packet in latest_packets:
        packets.append(
            [
                put_button(
                    "+",
                    onclick=lambda x=packet["_id"]: put_packet_search(x),
                    link_style=True,
                ),
                packet["src_ip"],
                packet["dest_ip"],
                packet["protocol"],
                packet["src_port"],
                packet["dest_port"],
                packet["action"],
            ]
        )
    put_markdown(f"### Packets from the last {HOURS_BACK} hours")
    put_table(tdata=packets, header=["More data", "Source IP", "Dest IP", "Protocol", "Src Port", "Dest port", "Action"])

@use_scope("dashboard", clear=True)
def manage_rules():
    put_markdown("## Manage Rules")

    # Get rules from MongoDB
    rules = get_rules()

    put_table(
        tdata=[
            [
                rule["src_ip"],
                rule["dest_ip"],
                rule["protocol"],
                rule["action"],
                put_button("Edit", onclick=lambda r=rule: edit_rule(r), small=True),
                put_button("Delete", onclick=lambda r=rule: delete_rule(r["_id"]), small=True),
            ]
            for rule in rules
        ],
        header=["Source IP", "Destination IP", "Protocol", "Action", "Edit", "Delete"]
    )

    # Add button for adding a new rule
    put_button("Add New Rule", onclick=lambda: add_rule(), color="primary", outline=True)


@use_scope("latest")
def get_rules():
    """Fetch rules from MongoDB."""
    rules_collection = db[Collections.RULES]
    rules = list(rules_collection.find())
    return [
        {
            "_id": str(rule.get("_id", "")),
            "src_ip": rule.get("src_ip", ""),
            "dest_ip": rule.get("dest_ip", ""),
            "protocol": rule.get("protocol", ""),
            "action": rule.get("action", "")
        }
        for rule in rules
    ]


@use_scope("latest")
def add_rule():
    """Show form to add a new rule and insert it into MongoDB."""
    new_rule = input_group("Add New Rule", [
        input("Source IP", name="src_ip"),
        input("Destination IP", name="dest_ip"),
        input("Protocol (e.g., TCP, UDP)", name="protocol"),
        input("Action (allow/deny)", name="action")
    ])
    # rule_set.add_rule(src_ip=new_rule["src_ip"], dest_ip=new_rule["dest_ip"], protocol=new_rule["protocol"], action=new_rule["action"])

    db[Collections.RULES].insert_one(new_rule)

    # Refresh the rules display
    manage_rules()


@use_scope("latest")
def edit_rule(rule):
    """Edit an existing rule."""
    updated_rule = input_group("Edit Rule", [
        input("Source IP", name="src_ip", value=rule["src_ip"]),
        input("Destination IP", name="dest_ip", value=rule["dest_ip"]),
        input("Protocol", name="protocol", value=rule["protocol"]),
        input("Action", name="action", value=rule["action"])
    ])

    # rule_set.edit_rule(rule["_id"], updated_rule)

    db[Collections.RULES].update_one({"_id": rule["_id"]}, {"$set": updated_rule})

    manage_rules()


@use_scope("latest")
def delete_rule(rule_id):
    """Delete a rule from MongoDB."""
    # rule_set.delete_rule(rule_id)
    db[Collections.RULES].delete_one({"_id": rule_id})

    manage_rules()


def start_dash_thread():
    dash_thread = Thread(target=run_dash_app)
    dash_thread.setDaemon(True)
    dash_thread.start()

# PyWebIO dashboard with embedded iframe
@use_scope("dashboard", clear=True)
def put_dashboard():
    put_markdown("## Dashboard")
    put_markdown("###### Network packet distribution across directions (IN vs OUT).")
    put_markdown("---")
    # Embed the Dash app into the PyWebIO dashboard using an iframe
    put_html('<iframe src="http://127.0.0.1:8050" width="100%" height="600" style="border:none;"></iframe>')


@use_scope("left_navbar")
def put_navbar():
    put_grid(
        [
            [
                put_markdown("### NetGuard"),
                put_image(open(os.path.join(images_dir, 'icon2.png'), 'rb').read(), format='png'),
                put_markdown("#### Packets").onclick(lambda: put_blocks()),
                put_markdown("#### Manage Rules").onclick(lambda: manage_rules()),
                put_markdown("#### Dashboard").onclick(lambda: put_dashboard()),
            ]
        ],
        direction="column",
    )


@config(theme="dark")
def main():
    start_dash_thread()
    session.set_env(title="NetGuard", output_max_width="100%")
    put_row(
        [put_scope("left_navbar"), None, put_scope("dashboard")],
        size="1fr 50px 4fr",
    )
    put_navbar()
    put_blocks()


if __name__ == "__main__":
    start_server(main, port=8081)
