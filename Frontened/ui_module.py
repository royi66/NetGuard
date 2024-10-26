from pywebio import *
from pywebio.output import *
from pywebio.input import *
import os
from netguard.handle_db import MongoDbClient
from netguard.consts import DBNames, Collections, Ui, Paths, FIELDS, LABELS
from datetime import timedelta, datetime
from netguard.rule_management import RuleSet
import matplotlib
from dash import Dash
from threading import Thread
from dashboard import run_dash_app
from functools import partial

matplotlib.use('Agg')
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
    query = {FIELDS.INSERTION_TIME: {"$gte": one_hour_ago}}

    skip = page * Ui.PAGE_SIZE
    matching_packets = list(packets_collection.find(query).skip(skip).limit(Ui.PAGE_SIZE))
    more_packets = packets_collection.count_documents(query) > (skip + Ui.PAGE_SIZE)

    return [
        {
            FIELDS.ID: packet.get(FIELDS.ID, None),
            FIELDS.DIRECTION: packet.get(FIELDS.DIRECTION, ""),
            FIELDS.SRC_IP: packet.get(FIELDS.SRC_IP, ""),
            FIELDS.DEST_IP: packet.get(FIELDS.DEST_IP, ""),
            FIELDS.SRC_PORT: packet.get(FIELDS.SRC_PORT, ""),
            FIELDS.DEST_PORT: packet.get(FIELDS.DEST_PORT, ""),
            FIELDS.PROTOCOL: packet.get(FIELDS.PROTOCOL, ""),
            FIELDS.MATCHED_RULE: packet.get(FIELDS.MATCHED_RULE, "")
        }
        for packet in matching_packets
    ], more_packets


def handle_pagination(rule_set, btn):
    # Function to handle pagination control clicks
    global current_page
    if btn == 'next':
        current_page += 1
    elif btn == 'prev' and current_page > 0:
        current_page -= 1

    update_packets_list(rule_set, current_page)


def update_packets_list(rule_set, page=0):
    global current_page
    current_page = page
    packets, has_next_page = get_recent_packets(current_page)

    # Calculate start and end packet numbers
    total_packets = db[Collections.PACKETS].count_documents(
        {FIELDS.INSERTION_TIME: {"$gte": datetime.now() - timedelta(hours=Ui.HOURS_BACK)}})
    start_packet = current_page * Ui.PAGE_SIZE + 1
    end_packet = start_packet + len(packets) - 1

    with use_scope('latest', clear=True):
        # Display packet range and total number of packets
        put_markdown(f"### Showing packets {start_packet}-{end_packet} out of {total_packets}")

        headers = ["More Info", "Direction", LABELS.SRC_IP, LABELS.DEST_IP, LABELS.PROTOCOL, LABELS.SRC_PORT,
                   LABELS.DEST_PORT, "Rule"]

        packet_rows = []
        for packet in packets:
            if packet[FIELDS.MATCHED_RULE]:
                if packet[FIELDS.MATCHED_RULE] > 0:
                    packet["rule"] = rule_set.get_rule_by_id(packet[FIELDS.MATCHED_RULE])

            packet_row = [
                put_button("+", onclick=lambda x=packet[FIELDS.ID]: put_packet_search(x), link_style=True),
                put_text(packet[FIELDS.DIRECTION]),
                put_text(packet[FIELDS.SRC_IP]),
                put_text(packet[FIELDS.DEST_IP]),
                put_text(packet[FIELDS.PROTOCOL]),
                put_text(packet[FIELDS.SRC_PORT]),
                put_text(packet[FIELDS.DEST_PORT])
            ]
            if packet.get(FIELDS.MATCHED_RULE):
                if packet[FIELDS.MATCHED_RULE] > 0:
                    packet_row.append(
                        put_button(packet[FIELDS.MATCHED_RULE],
                                   onclick=lambda x=packet[FIELDS.MATCHED_RULE]: rule_search(x, rule_set),
                                   color="danger").style(
                            'color: white; border: none; padding: 5px;')
                    )
            else:
                packet_row.append(put_text(""))  # Placeholder if no matched_rule_id

            packet_rows.append(packet_row)

        # Display the table with headers
        put_table(
            tdata=packet_rows,
            header=headers
        )

        # Pagination controls: Next and Previous buttons
        buttons = []
        if current_page > 0:
            buttons.append(put_button("Previous", onclick=lambda: handle_pagination(rule_set, 'prev'), color="warning"))
        if has_next_page:
            buttons.append(put_button("Next", onclick=lambda: handle_pagination(rule_set, 'next'), color="success"))

        if buttons:
            put_row(buttons, size="auto auto auto")


def rule_search(rule_id, rule_set):
    popup("Rule Info", [put_scope("popup_content")], PopupSize.LARGE)
    with use_scope("popup_content"):
        # Query MongoDB for the packet by src_ip
        rules = rule_set.get_rule_by_id(rule_id)

        if rules:
            put_table(
                tdata=[
                    [LABELS.RULE_ID, rules.get(FIELDS.RULE_ID, "")],
                    [LABELS.SRC_IP, rules.get(FIELDS.SRC_IP, "")],
                    [LABELS.DEST_IP, rules.get(FIELDS.DEST_IP, "")],
                    [LABELS.PROTOCOL, rules.get(FIELDS.PROTOCOL, "")],
                    [LABELS.ACTION, rules.get(FIELDS.ACTION, "")],
                    [LABELS.INSERTION_TIME, str(rules.get(FIELDS.INSERTION_TIME, ""))]
                ],
                header=["Field", "Value"]
            )
        else:
            put_markdown(f"**Packet not found**").style("color: red")


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
                    [LABELS.DIRECTION, packet.get(FIELDS.DIRECTION, "")],
                    [LABELS.SRC_IP, packet.get(FIELDS.SRC_IP, "")],
                    [LABELS.DEST_IP, packet.get(FIELDS.DEST_IP, "")],
                    [LABELS.PROTOCOL, packet.get(FIELDS.PROTOCOL, "")],
                    [LABELS.PROTOCOL_NUMBER, packet.get("protocol_num", "")],
                    [LABELS.TTL, packet.get("ttl", "")],
                    [LABELS.PACKET_LENGTH, packet.get("length", "")],
                    [LABELS.SRC_PORT, packet.get("src_port", "")],
                    [LABELS.DEST_PORT, packet.get("dest_port", "")],
                    [LABELS.MATCHED_RULE_ID, packet.get("matched_rule_id", "")],
                    [LABELS.FRAGMENT_OFFSET, packet.get("fragment_offset", "")],
                    [LABELS.MORE_FRAGMENTS, packet.get("more_fragments", "")],
                    [LABELS.PAYLOAD, packet.get("payload", "")],
                    [LABELS.INSERTION_TIME, str(packet.get("insertion_time", ""))]
                ],
                header=["Field", "Value"]
            )
        else:
            put_markdown(f"**Packet not found**").style("color: red")


@use_scope("dashboard", clear=True)
def put_blocks(rule_set):
    put_markdown("## Network Packets")
    put_scope("search")
    put_scope("results")
    put_scope("latest")

    with use_scope("search"):
        # Dropdown for choosing the search field
        pin.put_select(name='search_field', label='Select Field to Search', options=[
            (LABELS.DIRECTION, FIELDS.DIRECTION),
            (LABELS.SRC_IP, FIELDS.SRC_IP),
            (LABELS.DEST_IP, FIELDS.DEST_IP),
            (LABELS.PROTOCOL, FIELDS.PROTOCOL),
            (LABELS.SRC_PORT, FIELDS.SRC_PORT),
            (LABELS.DEST_PORT, FIELDS.DEST_PORT),
            ('Rule', FIELDS.MATCHED_RULE),
        ], value=FIELDS.DIRECTION)

        pin.put_input(name='search_value', placeholder="Enter value for the selected field")

        # Fetch field and value when the button is clicked
        put_button("Search", onclick=lambda: put_packet_search_results(pin.pin["search_field"], pin.pin["search_value"], rule_set), color="primary")


    put_latest_packets(rule_set)


def clear_filter(rule_set):
    """Clear the search filter and show all packets."""
    # Clear the input field values
    pin.pin["search_value"] = ""

    # Clear results scope and show all packets
    with use_scope("results", clear=True):
        pass
    put_latest_packets(rule_set)


@use_scope("results", clear=True)
def put_packet_search_results(field, value, rule_set):
    """Fetch and filter packets based on the search field and value, and update the existing table."""
    try:
        filtered_packets = mongo_client.get_data_by_field(DBNames.NET_GUARD_DB, Collections.PACKETS, field, value)

        update_packets_list_with_filter(filtered_packets)

        if value:
            put_clear_filter_button(rule_set)

    except Exception as e:
        print(f"Error: {e}")
        put_text("Error fetching search results.").style("color: red;")


def put_clear_filter_button(rule_set):
    """Display the Clear Filter button to reset the search filter."""
    with use_scope("results", clear=False):
        put_button("Clear Filter", onclick=lambda: clear_filter(rule_set), color="warning", outline=True)


def update_packets_list_with_filter(filtered_packets):
    """Update the existing packets table with filtered packets based on search criteria."""
    with use_scope('latest', clear=True):
        put_markdown(f"### Showing filtered packets")

        headers = ["More Info", "Direction", LABELS.SRC_IP, LABELS.DEST_IP, LABELS.PROTOCOL, LABELS.SRC_PORT, LABELS.DEST_PORT, "Rule"]

        packet_rows = []
        for packet in filtered_packets:
            matched_rule_id = packet.get("matched_rule_id", None)  # Safely fetch `matched_rule_id`

            if matched_rule_id:
                if matched_rule_id > 0:
                    packet["rule"] = rule_set.get_rule_by_id(matched_rule_id)

            packet_row = [
                put_button("+", onclick=lambda x=packet[FIELDS.ID]: put_packet_search(x), link_style=True),
                put_text(packet.get(FIELDS.DIRECTION, "")),
                put_text(packet.get(FIELDS.SRC_IP, "")),
                put_text(packet.get(FIELDS.DEST_IP, "")),
                put_text(packet.get(FIELDS.PROTOCOL, "")),
                put_text(packet.get(FIELDS.SRC_PORT, "")),
                put_text(packet.get(FIELDS.DEST_PORT, "")),
            ]

            if matched_rule_id and matched_rule_id > 0:
                packet_row.append(
                    put_button(str(matched_rule_id),
                               onclick=lambda x=matched_rule_id: rule_search(x, rule_set),
                               color="danger").style('background-color: red; color: white; border: none; padding: 5px;')
                )
            else:
                packet_row.append(put_text(""))

            packet_rows.append(packet_row)

        put_table(
            tdata=packet_rows,
            header=headers
        )


@use_scope("latest")
def put_latest_packets(rule_set):
    global current_page
    update_packets_list(rule_set, current_page)


def show_packets_for_rule(rule_id, rule_set):
    """Redirect to the packets page and apply a filter based on the selected rule ID."""
    field = FIELDS.MATCHED_RULE
    value = rule_id

    with use_scope("dashboard", clear=True):
        put_blocks_with_filter(field, value, rule_set)


def put_blocks_with_filter(field, value, rule_set):
    """Display the packets page with a specific filter applied."""
    put_markdown("## Network Packets")
    put_scope("search")
    put_scope("results")
    put_scope("latest")

    with use_scope("search"):
        # Dropdown for choosing the search field
        pin.put_select(name='search_field', label='Select Field to Search', options=[
            ('Direction', 'direction'),
            ('Source IP', FIELDS.SRC_IP),
            ('Destination IP', FIELDS.DEST_IP),
            ('Protocol', FIELDS.PROTOCOL),
            ('Source Port', FIELDS.SRC_PORT),
            ('Destination Port', FIELDS.DEST_PORT),
            ('Rule', FIELDS.MATCHED_RULE),
        ], value=field)  # Set the dropdown to match the rule field

        pin.put_input(name='search_value', placeholder="Enter value for the selected field", value=value)

        put_button("Search", onclick=lambda: put_packet_search_results(field, value, rule_set), color="primary")

    # Directly display the filtered packets
    put_packet_search_results(field, value, rule_set)


def show_add_rule_form(rule_set):
    """Show the form and hide the Add New Rule button."""
    clear("rules_table")
    clear("add_button")
    add_rule(rule_set)

@use_scope("latest")
def get_rules(rule_set):
    """Fetch rules from MongoDB."""
    return rule_set.get_all_rules()


@use_scope("latest")
def add_rule(rule_set):
    """Show form to add a new rule and insert it into MongoDB directly under the Add New Rule button."""
    put_html(Ui.DARK_MODE_CSS)

    advanced_visible = False

    def toggle_advanced():
        nonlocal advanced_visible
        advanced_visible = not advanced_visible
        show_advanced_fields(advanced_visible)

    with use_scope("add_rule_form", clear=True):  # Clear the scope to avoid form duplication
        put_markdown("### Add New Rule")

        # Separate inputs without input_group
        pin.put_input(FIELDS.SRC_IP, label="Source IP")
        pin.put_input(FIELDS.DEST_IP, label="Destination IP")
        pin.put_input(FIELDS.PROTOCOL, label="Protocol (e.g., TCP, UDP)")

        pin.put_select(FIELDS.ACTION, label="Action", options=[
            {'label': 'Allow', 'value': 'allow'},
            {'label': 'Deny', 'value': 'deny'}
        ])
        pin.put_select(FIELDS.ALERT, label="Alert", options=[
            {'label': 'On', 'value': 'on'},
            {'label': 'Off', 'value': 'off'}
        ])

        put_button("Advanced", onclick=toggle_advanced, outline=True, color="info")

        put_scope("advanced_fields")
        put_buttons(
            buttons=[
                {'label': 'Submit', 'value': 'submit', 'color': 'success'},
                {'label': 'Cancel', 'value': 'cancel', 'color': 'danger'}
            ],
            onclick=lambda btn: handle_rule_form_action(btn, rule_set)
        )


def show_advanced_fields(visible):
    """Show or hide the advanced fields based on visibility toggle."""
    with use_scope("advanced_fields", clear=True):
        if visible:
            put_markdown("### Advanced Options")
            pin.put_input(FIELDS.TTL, label="TTL (Time To Live)")
            pin.put_input(FIELDS.TCP_FLAGS, label="TCP Flags")
            pin.put_input(FIELDS.CHECKSUM, label="Checksum")


def handle_rule_form_action(action, rule_set):
    """Handle the form submission or cancellation."""
    if action == 'submit':
        new_rule = {
            FIELDS.SRC_IP: pin.pin[FIELDS.SRC_IP],
            FIELDS.DEST_IP: pin.pin[FIELDS.DEST_IP],
            FIELDS.PROTOCOL: pin.pin[FIELDS.PROTOCOL],
            FIELDS.ACTION: pin.pin[FIELDS.ACTION],
            FIELDS.TTL: pin.pin[FIELDS.TTL],
            FIELDS.CHECKSUM: pin.pin[FIELDS.CHECKSUM],
            FIELDS.TCP_FLAGS: pin.pin[FIELDS.TCP_FLAGS],
            "alert": pin.pin["alert"]
        }
        rule_set.add_rule(src_ip=new_rule[FIELDS.SRC_IP], dest_ip=new_rule[FIELDS.DEST_IP],
                 protocol=new_rule[FIELDS.PROTOCOL], action=new_rule[FIELDS.ACTION], ttl=new_rule[FIELDS.TTL],
                 checksum=new_rule[FIELDS.CHECKSUM], tcp_flags=new_rule[FIELDS.TCP_FLAGS], alert=new_rule["alert"])

        manage_rules(rule_set)
    elif action == 'cancel':
        clear("add_rule_form")
        manage_rules(rule_set)


@use_scope("latest")
def edit_rule(rule, rule_set):
    """Edit an existing rule."""
    updated_rule = input_group("Edit Rule", [
        input(LABELS.SRC_IP, name=FIELDS.SRC_IP, value=rule[FIELDS.SRC_IP]),
        input(LABELS.DEST_IP, name=FIELDS.DEST_IP, value=rule[FIELDS.DEST_IP]),
        input(LABELS.PROTOCOL, name=FIELDS.PROTOCOL, value=rule[FIELDS.PROTOCOL]),
        input("Action", name=FIELDS.ACTION, value=rule[FIELDS.ACTION])
    ])

    rule_set.edit_rule(rule[FIELDS.RULE_ID], **updated_rule)

    manage_rules(rule_set)


@use_scope("latest")
def delete_rule(rule_id, rule_set):
    """Delete a rule from MongoDB."""
    rule_set.delete_rule(rule_id)
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
    iframe_style = 'border:#1f1f1f; background-color:#1f1f1f;'
    iframe_html = f'<iframe src="http://127.0.0.1:8050" width="100%" height="1000" style="{iframe_style}"></iframe>'

    put_html(iframe_html)


def toggle_button(rule_id, is_on, rule_set):
    """
    Returns a toggle button that calls toggle_alert when clicked.

    Parameters:
    - rule_id: ID of the rule to toggle.
    - is_on: Boolean indicating the current state of the toggle (True for "on", False for "off").
    """
    label = "ON" if is_on else "OFF"
    color = "success" if is_on else "warning"

    return put_button(label, color=color, onclick=lambda: toggle_alert(rule_id, rule_set))


@config(title="Toggle Alert")
def toggle_alert(rule_id, rule_set):
    """Toggle the alert field for a specific rule by rule_id."""
    rule = rule_set.get_rule_by_id(rule_id)

    if rule:
        new_alert_status = "on" if rule[FIELDS.ALERT] == "off" else "off"
        rule_set.edit_rule(rule_id, **{FIELDS.ALERT: new_alert_status})
        manage_rules(rule_set)


@use_scope("dashboard", clear=True)
def manage_rules(rule_set):
    put_markdown("## Manage Rules")
    rules = get_rules(rule_set)
    with use_scope("rules_table", clear=True):
        if rules:
            put_table(
                tdata=[
                    [
                        put_button("Get Packets", onclick=partial(show_packets_for_rule, rule[FIELDS.RULE_ID], rule_set), small=True),
                        rule[FIELDS.SRC_IP],
                        rule[FIELDS.DEST_IP],
                        rule[FIELDS.PROTOCOL],
                        rule[FIELDS.TCP_FLAGS],
                        rule[FIELDS.TTL],
                        rule[FIELDS.CHECKSUM],
                        rule[FIELDS.ACTION],
                        toggle_cell(rule[FIELDS.RULE_ID], rule[FIELDS.ALERT] == "on", rule_set),
                        put_row([
                            put_button("Edit", onclick=lambda r=rule: edit_rule(r, rule_set), small=True),
                            put_button("Delete", onclick=lambda r=rule: delete_rule(r[FIELDS.RULE_ID], rule_set), small=True)
                        ], size="auto auto")
                    ]
                    for rule in rules
                ],
                header=["Get Packets", LABELS.RULE_ID, LABELS.SRC_IP, LABELS.DEST_IP, LABELS.PROTOCOL, "Tcp Flags",
                        LABELS.TTL, "Checksum", "Action", "Alert", ""]
                )

        with use_scope("add_button", clear=True):
            put_button("Add New Rule", onclick=lambda: show_add_rule_form(rule_set), color="primary", outline=True)


def toggle_cell(rule_id, is_on, rule_set):
    """Generate a toggle button cell that updates only when toggled."""
    label = "ON" if is_on else "OFF"
    color = "success" if is_on else "warning"

    return put_button(label, color=color,
                      onclick=lambda: toggle_alert(rule_id, rule_set))


@use_scope("left_navbar")
def put_navbar(rule_set):
    put_html(Ui.DARK_MODE_CSS)
    put_grid(
        [
            [
                put_markdown("### NetGuard", 'sidebar-item'),
                put_image(open(os.path.join(images_dir, Paths.ICON_URL), 'rb').read(), format='png')
                .style("width: 150px; height: auto; background-color: #1f1f1f; margin-left: -20px;"),
                put_markdown("#### Packets", 'sidebar-item').onclick(lambda: put_blocks(rule_set)),
                put_markdown("#### Manage Rules", 'sidebar-item').onclick(lambda: manage_rules(rule_set)),
                put_markdown("#### Dashboard", 'sidebar-item').onclick(lambda: put_dashboard()),
            ]
        ],
        direction="column",
    )


@config(theme="dark")
def main(rule_set):
    start_dash_thread()
    session.set_env(title="NetGuard", output_max_width="100%",)
    put_html(Ui.DARK_MODE_CSS)

    put_row(
        [put_scope("left_navbar"), None, put_scope("dashboard")],
        size="0.5fr 20px 4fr",
    )
    put_navbar(rule_set)
    put_blocks(rule_set)


if __name__ == "__main__":
    db_client = MongoDbClient()
    rule_set = RuleSet(db_client)
    start_server(lambda: main(rule_set), port=8081)