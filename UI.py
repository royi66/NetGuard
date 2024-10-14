from pywebio import *
from pywebio.output import *
from pywebio.input import *
from pymongo import MongoClient
import os

# MongoDB connection (adjust with your own)
client = MongoClient("mongodb://localhost:27017/")
db = client.network_scanner

# Mock scanning function (replace with actual network packet fetching)
def scan_network():
    # Simulated network packets with source IP, destination IP, protocol, and action
    return [
        {"src_ip": "192.168.0.1", "dest_ip": "192.168.0.2", "protocol": "TCP", "action": "allow"},
        {"src_ip": "192.168.0.3", "dest_ip": "192.168.0.4", "protocol": "UDP", "action": "deny"},
    ]

def put_packet_search(src_ip):
    popup("Packet Info", [put_scope("popup_content")], PopupSize.LARGE)
    with use_scope("popup_content"):
        # Query MongoDB for matching packets
        packet = db.packets.find_one({"src_ip": src_ip})
        if packet:
            put_table(
                tdata=[
                    ["Source IP", packet['src_ip']],
                    ["Destination IP", packet['dest_ip']],
                    ["Protocol", packet['protocol']],
                    ["Action", packet['action']]
                ],
                header=["Properties", "Values"]
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
        put_row(
            [
                pin.put_input(
                    type=TEXT,
                    name="packet_search",
                    placeholder="Enter Source IP to lookup",
                ),
                None,
                put_button(
                    "Search",
                    onclick=lambda: put_packet_search(pin.pin["packet_search"]),
                    outline=True,
                ),
            ],
            size="40% 10px 15%",
        )
    put_latest_packets()

@use_scope("results", clear=True)
def put_packet_search_results(src_ip):
    if src_ip:
        try:
            packet = db.packets.find_one({"src_ip": src_ip})
            if packet:
                put_markdown(f"### Packet from {packet['src_ip']}")
                put_table(
                    tdata=[
                        ["Source IP", packet["src_ip"]],
                        ["Destination IP", packet["dest_ip"]],
                        ["Protocol", packet["protocol"]],
                        ["Action", packet["action"]],
                    ],
                    header=["Properties", "Values"],
                )
            else:
                put_text("Packet not found.")
        except Exception as e:
            print(f"Error: {e}")

@use_scope("latest")
def put_latest_packets():
    latest_packets = scan_network()  # Replace with real scanning function
    packets = []
    for packet in latest_packets:
        packets.append(
            [
                put_button(
                    packet["src_ip"],
                    onclick=lambda x=packet["src_ip"]: put_packet_search(x),
                    link_style=True,
                ),
                packet["protocol"],
                packet["action"],
            ]
        )
    put_markdown("### Latest Packets")
    put_table(tdata=packets, header=["Source IP", "Protocol", "Action"])

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
                put_markdown("### Network Scanner"),
                put_markdown("#### Packets").onclick(lambda: put_blocks()),
                put_markdown("#### Dashboard").onclick(lambda: put_dashboard()),
            ]
        ],
        direction="column",
    )

@config(theme="dark")
def main():
    session.set_env(title="Network Scanner", output_max_width="100%")
    put_row(
        [put_scope("left_navbar"), None, put_scope("dashboard")],
        size="1fr 50px 4fr",
    )
    put_navbar()
    put_blocks()

if __name__ == "__main__":
    start_server(main, port=8080)
