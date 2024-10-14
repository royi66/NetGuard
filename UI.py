from pywebio import *
from pywebio.output import *
from pywebio.input import *
from pymongo import MongoClient
import os
from netguard.handle_db import MongoDbClient
from netguard.consts import DBNames, Collections, HOURS_BACK
from datetime import timedelta, datetime

mongo_client = MongoDbClient()
db = mongo_client.client[DBNames.NET_GUARD_DB]


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

@use_scope("dashboard", clear=True)
def put_dashboard():
    put_markdown("## Dashboard")
    put_html("<canvas id='myChart'></canvas>").style("width: 60vw; height: 40rem")
    put_markdown("###### Network packet distribution across protocols.")
    put_markdown("---")

@use_scope("left_navbar")
def put_navbar():
    put_grid(
        [
            [
                put_markdown("### NetGuard"),
                put_markdown("#### Packets").onclick(lambda: put_blocks()),
                put_markdown("#### Manage Rules").onclick(lambda: manage_rules()),
                put_markdown("#### Dashboard").onclick(lambda: put_dashboard()),
            ]
        ],
        direction="column",
    )


@config(theme="dark")
def main():
    session.set_env(title="NetGuard", output_max_width="100%")
    put_row(
        [put_scope("left_navbar"), None, put_scope("dashboard")],
        size="1fr 50px 4fr",
    )
    put_navbar()
    put_blocks()


if __name__ == "__main__":
    start_server(main, port=8080)
