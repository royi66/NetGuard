from pywebio import *
from pywebio.output import *
from pywebio.input import *
import os
from handle_db import MongoDbClient
from consts import DBNames, Collections, Ui, Paths, FIELDS, LABELS
from datetime import timedelta, datetime
from rule_management import RuleSet
import matplotlib
matplotlib.use('Agg')
from dash import Dash
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

    with use_scope('latest', clear=True):
        put_markdown(f"### Showing packets for page {current_page + 1}")

        headers = ["More Info", "Direction", LABELS.SRC_IP, LABELS.DEST_IP, LABELS.PROTOCOL, LABELS.SRC_PORT, LABELS.DEST_PORT, "Rule"]

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
                                   color="danger").style('background-color: red; color: white; border: none; padding: 5px;')
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
    print("???", value)
    """Fetch and filter packets based on the search field and value, and update the existing table."""
    try:
        # Fetch filtered packets from MongoDB based on the search field and value
        filtered_packets = mongo_client.get_data_by_field(DBNames.NET_GUARD_DB, Collections.PACKETS, field, value)

        # Directly update the table by reusing the existing `update_packets_list` functionality
        update_packets_list_with_filter(filtered_packets)

        # Show "Clear Filter" button if a filter is applied
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

        # Create headers for the table
        headers = ["More Info", "Direction", LABELS.SRC_IP, LABELS.DEST_IP, LABELS.PROTOCOL, LABELS.SRC_PORT, LABELS.DEST_PORT, "Rule"]

        # Create rows for the filtered packets
        packet_rows = []
        for packet in filtered_packets:
            rule_style = ''
            matched_rule_id = packet.get("matched_rule_id", None)  # Safely fetch `matched_rule_id`

            if matched_rule_id:
                if matched_rule_id > 0:
                    packet["rule"] = rule_set.get_rule_by_id(matched_rule_id)
                    rule_style = 'color: red;'

            # Create the row data
            packet_row = [
                put_button("+", onclick=lambda x=packet["_id"]: put_packet_search(x), link_style=True),
                put_text(packet.get(FIELDS.DIRECTION, "")),
                put_text(packet.get(FIELDS.SRC_IP, "")),
                put_text(packet.get(FIELDS.DEST_IP, "")),
                put_text(packet.get(FIELDS.PROTOCOL, "")),
                put_text(packet.get("src_port", "")),
                put_text(packet.get("dest_port", "")),
            ]

            if matched_rule_id and matched_rule_id > 0:
                packet_row.append(
                    put_button(str(matched_rule_id),
                               onclick=lambda x=matched_rule_id: rule_search(x, rule_set),
                               color="danger").style('background-color: red; color: white; border: none; padding: 5px;')
                )
            else:
                packet_row.append(put_text(""))  # Placeholder if no matched_rule_id

            packet_rows.append(packet_row)

        # Display the table with headers
        put_table(
            tdata=packet_rows,
            header=headers
        )



@use_scope("latest")
def put_latest_packets(rule_set):
    global current_page  # Ensure the current page is tracked
    update_packets_list(rule_set, current_page)


def show_add_alert_form(rule_set, rule_id=None):
    """Display the form for adding a new alert."""
    clear("alerts_table")
    clear("add_alert_button")

    put_markdown("### Add New Alert")

    # Form fields for the alert
    pin.put_input("alert_name", label="Alert Name")
    pin.put_textarea("description", label="Description")
    if rule_id:
        pin.put_input("rule_id", label="Rule ID", value=str(rule_id), readonly=True)
    else:
        pin.put_input("rule_id", label="Rule ID")


def show_packets_for_rule(rule, rule_set):
    """Redirect to the packets page and apply a filter based on the selected rule."""
    field = FIELDS.MATCHED_RULE
    value = rule.get(FIELDS.RULE_ID)

    # Update the blocks to display packets with the applied filter
    with use_scope("dashboard", clear=True):
        # Directly call the `put_blocks` function and pass the rule filter
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
            (LABELS.DIRECTION, FIELDS.DIRECTION),
            (LABELS.SRC_IP, FIELDS.SRC_IP),
            (LABELS.DEST_IP, FIELDS.DEST_IP),
            (LABELS.PROTOCOL, FIELDS.PROTOCOL),
            (LABELS.SRC_PORT, FIELDS.SRC_PORT),
            (LABELS.DEST_PORT, FIELDS.DEST_PORT),
            ('Rule', FIELDS.MATCHED_RULE),
        ], value=field)  # Set the dropdown to match the rule field

        pin.put_input(name='search_value', placeholder="Enter value for the selected field", value=value)

        put_button("Search", onclick=lambda: put_packet_search_results(field, value, rule_set), color="primary")

    put_packet_search_results(field, value, rule_set)


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

    # State to track if the advanced options should be shown
    advanced_visible = False

    def toggle_advanced():
        nonlocal advanced_visible
        advanced_visible = not advanced_visible
        show_advanced_fields(advanced_visible)  # Show/hide advanced fields based on toggle

    # Display the input fields for adding a new rule directly below the Add New Rule button
    with use_scope("add_rule_form", clear=True):  # Clear the scope to avoid form duplication
        put_markdown("### Add New Rule")

        pin.put_input(FIELDS.SRC_IP, label=LABELS.SRC_IP)
        pin.put_input(FIELDS.DEST_IP, label=LABELS.DEST_IP)
        pin.put_input(FIELDS.PROTOCOL, label="Protocol (e.g., TCP, UDP)")

        pin.put_select(FIELDS.ACTION, label="Action", options=[
            {'label': 'Allow', 'value': 'allow'},
            {'label': 'Deny', 'value': 'deny'}
        ])
        pin.put_select(FIELDS.ACTION, label="Alert", options=[
            {'label': 'OFF', 'value': 'off'},
            {'label': 'On', 'value': 'on'}
        ])

        # Button to toggle advanced options
        put_button("Advanced", onclick=toggle_advanced, outline=True, color="info")

        # Placeholder for advanced fields, added above the Submit and Cancel buttons
        put_scope("advanced_fields")

        # Display the buttons below the input fields
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
        input(LABELS.SRC_IP, name=FIELDS.SRC_IP, value=rule[FIELDS.SRC_IP]),
        input(LABELS.DEST_IP, name=FIELDS.DEST_IP, value=rule[FIELDS.DEST_IP]),
        input(LABELS.PROTOCOL, name=FIELDS.PROTOCOL, value=rule[FIELDS.PROTOCOL]),
        input("Action", name=FIELDS.ACTION, value=rule[FIELDS.ACTION])
    ])

    rule_set.edit_rule(rule[FIELDS.RULE_ID], **updated_rule)  # Update in the database

    # Return to manage_rules to see the updated list with fresh data
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

    # Use put_button to toggle the alert status
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
    put_html(Ui.TOGGLE_CSS)
    put_markdown("## Manage Rules")

    rules = get_rules(rule_set)

    if rules:
        headers = ["Get Packets", LABELS.RULE_ID, LABELS.SRC_IP, LABELS.DEST_IP, LABELS.PROTOCOL,
                   "Tcp Flags", LABELS.TTL, "Checksum", "Action", "Alert", ""]

        rows = [
            [
                put_button("Get Packets", onclick=lambda r=rule: show_packets_for_rule(r, rule_set), small=True),
                rule[FIELDS.RULE_ID],
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
        ]

        # Display table with dynamic rows
        put_table(rows, header=headers)


def toggle_cell(rule_id, is_on, rule_set):
    """Generate a toggle button cell that updates only when toggled."""
    label = "ON" if is_on else "OFF"
    color = "success" if is_on else "warning"

    return put_button(label, color=color,
                      onclick=lambda: toggle_alert(rule_id, rule_set))


@use_scope("left_navbar")
def put_navbar(rule_set):
    put_html(Ui.DARK_MODE_CSS)  # Apply the dark mode CSS
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
    session.set_env(title="NetGuard", output_max_width="100%",)  # Apply the theme dynamically
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
