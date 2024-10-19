from pywebio import *
from pywebio.output import *
from pywebio.input import *
import os
from handle_db import MongoDbClient
from consts import DBNames, Collections, Ui, Paths
from datetime import timedelta, datetime
from rule_management import Rule, RuleSet
import matplotlib
matplotlib.use('Agg')  # Use non-GUI backend
from dash import Dash, dcc, html
from threading import Thread
from dashboard import run_dash_app

app = Dash(__name__)
mongo_client = MongoDbClient()
db = mongo_client.client[DBNames.NET_GUARD_DB]
images_dir = os.path.join(os.path.dirname(__file__), '../Images')
current_page = 0


def get_recent_packets(page=0):
    """Retrieve 20 packets per page with pagination."""
    packets_collection = db[Collections.PACKETS]
    one_hour_ago = datetime.now() - timedelta(hours=Ui.HOURS_BACK)

    # Query to find packets in the last hour
    query = {"insertion_time": {"$gte": one_hour_ago}}

    skip = page * Ui.PAGE_SIZE
    matching_packets = list(packets_collection.find(query).skip(skip).limit(Ui.PAGE_SIZE))
    more_packets = packets_collection.count_documents(query) > (skip + Ui.PAGE_SIZE)

    return [
        {
            "_id": packet.get("_id", None),
            "direction": packet.get("direction", ""),
            "src_ip": packet.get("src_ip", ""),
            "dest_ip": packet.get("dest_ip", ""),
            "src_port": packet.get("src_port", ""),
            "dest_port": packet.get("dest_port", ""),
            "protocol": packet.get("protocol", ""),
            "action": packet.get("action", "")
        }
        for packet in matching_packets
    ], more_packets


def handle_pagination(btn):
    # Function to handle pagination control clicks
    global current_page
    if btn == 'next':
        current_page += 1
    elif btn == 'prev' and current_page > 0:
        current_page -= 1

    update_packets_list(current_page)


def update_packets_list(page=0):
    global current_page
    current_page = page
    packets, has_next_page = get_recent_packets(current_page)

    with use_scope('latest', clear=True):
        put_markdown(f"### Showing packets for page {current_page + 1}")
        # Create table structure with the "+" button
        packet_rows = []
        for packet in packets:
            packet_rows.append([
                put_button("+", onclick=lambda x=packet["_id"]: put_packet_search(x), link_style=True),
                packet["direction"],
                packet["src_ip"],
                packet["dest_ip"],
                packet["protocol"],
                packet["src_port"],
                packet["dest_port"],
                packet["action"]
            ])

        put_table(tdata=packet_rows, header=["More Info", "Direction", "Source IP", "Destination IP", "Protocol", "Source Port", "Destination Port", "Action"])

        # Pagination controls: Next and Previous buttons
        buttons = []
        if current_page > 0:
            buttons.append(put_button("Previous", onclick=lambda: handle_pagination('prev'), color="warning"))
        if has_next_page:
            buttons.append(put_button("Next", onclick=lambda: handle_pagination('next'), color="success"))

        if buttons:
            put_row(buttons, size="auto auto auto")


def put_packet_search(packet_id):
    """Retrieve and display the packet details based on src_ip or packet_id."""
    popup("Packet Info", [put_scope("popup_content")], PopupSize.LARGE)
    with use_scope("popup_content"):
        # Query MongoDB for the packet by src_ip
        packet = mongo_client.get_data_by_field(DBNames.NET_GUARD_DB, Collections.PACKETS, "_id", packet_id)

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
            ('Direction', 'direction'),
            ('Source IP', 'src_ip'),
            ('Destination IP', 'dest_ip'),
            ('Protocol', 'protocol'),
        ], value='direction')
        selected_field = pin.pin['search_field']
        defined_value = pin.pin["search_value"]

        # Input for search query
        pin.put_input(name='search_value', placeholder="Enter value for the selected field")

        put_button(
            "Search",
            onclick=lambda: put_packet_search_results(
                field=selected_field, value=defined_value
            ),
            outline=True,
        )

    put_latest_packets()


@use_scope("results", clear=True)
def put_packet_search_results(field, value):
    try:
        packets = mongo_client.get_data_by_field(DBNames.NET_GUARD_DB, Collections.PACKETS, field, value)

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
    global current_page  # Ensure the current page is tracked
    update_packets_list(current_page)


@use_scope("dashboard", clear=True)
def manage_rules(rule_set):
    put_markdown("## Manage Rules")
    # Get rules from MongoDB
    rules = get_rules(rule_set)
    with use_scope("rules_table", clear=True):
        if rules:
            put_table(
                tdata=[
                    [
                        rule["src_ip"],
                        rule["dest_ip"],
                        rule["protocol"],
                        rule["action"],
                        put_row([
                            put_button("Edit", onclick=lambda r=rule: edit_rule(r, rule_set), small=True),
                            put_button("Delete", onclick=lambda r=rule: delete_rule(r["_id"], rule_set), small=True)
                        ], size="auto auto")
                    ]
                    for rule in rules
                ],
                header=["Source IP", "Destination IP", "Protocol", "Action", ""]
            )

    # Use a scope for the Add New Rule button, so it can be cleared when needed
    with use_scope("add_button", clear=True):
        put_button("Add New Rule", onclick=lambda: show_add_rule_form(rule_set), color="primary", outline=True)


def show_add_rule_form(rule_set):
    """Show the form and hide the Add New Rule button."""
    clear("rules_table")
    clear("add_button")  # Clear the add button scope to hide the button
    add_rule(rule_set)  # Display the form for adding a new rule


@use_scope("latest")
def get_rules(rule_set):
    """Fetch rules from MongoDB."""
    return rule_set.get_all_rules()


@use_scope("latest")
def add_rule(rule_set):
    """Show form to add a new rule and insert it into MongoDB directly under the Add New Rule button."""
    put_html(Ui.DARK_MODE_CSS)  # Apply the dark mode CSS globally

    # Display the input fields for adding a new rule directly below the Add New Rule button
    with use_scope("add_rule_form", clear=True):  # Clear the scope to avoid form duplication
        put_markdown("### Add New Rule")

        # Separate inputs without input_group
        pin.put_input("src_ip", label="Source IP")
        pin.put_input("dest_ip", label="Destination IP")
        pin.put_input("protocol", label="Protocol (e.g., TCP, UDP)")
        pin.put_input("action", label="Action (allow/deny)")

        # Display the buttons below the input fields
        put_buttons(
            buttons=[
                {'label': 'Submit', 'value': 'submit', 'color': 'success'},
                {'label': 'Cancel', 'value': 'cancel', 'color': 'danger'}
            ],
            onclick=lambda btn: handle_rule_form_action(btn, rule_set)
        )


def handle_rule_form_action(action, rule_set):
    #TODO: Add validation and fix submit butting when no input is given (display error)
    """Handle the form submission or cancellation."""
    if action == 'submit':
        # Fetch the input data using pin
        new_rule = {
            "src_ip": pin.pin['src_ip'],
            "dest_ip": pin.pin['dest_ip'],
            "protocol": pin.pin['protocol'],
            "action": pin.pin['action']
        }
        rule_set.add_rule(**new_rule)  # Add the new rule to the database

        # Refresh the rules display after adding the new rule
        manage_rules(rule_set)
    elif action == 'cancel':
        # If the cancel button is clicked, clear the form and go back to manage_rules
        clear("add_rule_form")
        manage_rules(rule_set)  # Refresh the rules view after cancellation


@use_scope("latest")
def edit_rule(rule, rule_set):
    """Edit an existing rule."""
    updated_rule = input_group("Edit Rule", [
        input("Source IP", name="src_ip", value=rule["src_ip"]),
        input("Destination IP", name="dest_ip", value=rule["dest_ip"]),
        input("Protocol", name="protocol", value=rule["protocol"]),
        input("Action", name="action", value=rule["action"])
    ])

    rule_set.edit_rule(rule["_id"], updated_rule)

    # db[Collections.RULES].update_one({"_id": rule["_id"]}, {"$set": updated_rule})

    manage_rules(rule_set)


@use_scope("latest")
def delete_rule(rule_id, rule_set):
    """Delete a rule from MongoDB."""
    rule_set.delete_rule(rule_id)
    # db[Collections.RULES].delete_one({"_id": rule_id})

    manage_rules(rule_set)


def start_dash_thread():
    dash_thread = Thread(target=run_dash_app)
    dash_thread.setDaemon(True)
    dash_thread.start()


@use_scope("dashboard", clear=True)
def put_dashboard():
    put_markdown("## Dashboard")
    put_markdown("###### Network packet distribution across directions (IN vs OUT).")
    put_markdown("---")
    # Embed the Dash app into the PyWebIO dashboard using an iframe
    # Set iframe container to dark mode
    iframe_style = 'border:#1f1f1f; background-color:#1f1f1f;'
    iframe_html = f'<iframe src="http://127.0.0.1:8050" width="100%" height="1000" style="{iframe_style}"></iframe>'

    # Embed the Dash app into the PyWebIO dashboard using an iframe
    put_html(iframe_html)


@use_scope("left_navbar")
def put_navbar(rule_set):
    put_html(Ui.DARK_MODE_CSS)  # Apply the dark mode CSS
    put_grid(
        [
            [
                put_markdown("### NetGuard", 'sidebar-item'),
                put_image(open(os.path.join(images_dir, Paths.ICON_URL), 'rb').read(), format='png')
                .style("width: 150px; height: auto; background-color: #1f1f1f; margin-left: -20px;"),
                put_markdown("#### Packets", 'sidebar-item').onclick(lambda: put_blocks()),
                put_markdown("#### Manage Rules", 'sidebar-item').onclick(lambda: manage_rules(rule_set)),
                put_markdown("#### Dashboard", 'sidebar-item').onclick(lambda: put_dashboard()),
            ]
        ],
        direction="column",
    )


@config(theme="dark")
def main(rule_set):
    start_dash_thread()
    session.set_env(title="NetGuard", output_max_width="100%",)  # Apply the theme dynamically
    put_html(Ui.DARK_MODE_CSS)

    put_row(
        [put_scope("left_navbar"), None, put_scope("dashboard")],
        size="0.5fr 20px 4fr",
    )
    put_navbar(rule_set)
    put_blocks()


if __name__ == "__main__":
    db_client = MongoDbClient()
    rule_set = RuleSet(db_client)
    start_server(lambda: main(rule_set), port=8081)
