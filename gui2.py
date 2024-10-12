import sys
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QTableWidget, QTableWidgetItem, QMainWindow, QLabel
from PyQt5.QtWidgets import QDialog, QFormLayout, QLineEdit, QDialogButtonBox
from pymongo import MongoClient
import matplotlib.pyplot as plt
from io import BytesIO
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from HandleDB import MongoDbClient
from consts import DBNames, Collections


class NetworkScanner(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Network Scanner")

        # Create the main layout
        layout = QVBoxLayout()

        # Add buttons to switch between sections
        self.btn_manage_rules = QPushButton("Manage Rules")
        self.btn_dashboard = QPushButton("Dashboard")

        # Connect buttons to their actions
        self.btn_manage_rules.clicked.connect(self.show_manage_rules)
        self.btn_dashboard.clicked.connect(self.show_dashboard)

        # Add buttons to layout
        layout.addWidget(self.btn_manage_rules)
        layout.addWidget(self.btn_dashboard)

        # Set the central widget
        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

        self.rules = [
            {"src_ip": "66.203.125.12", "dest_ip": "192.168.10.30", "protocol": "TCP", "action": "allow"},
            {"src_ip": "192.168.1.2", "dest_ip": "10.0.0.10", "protocol": "UDP", "action": "deny"},
        ]

    def show_manage_rules(self):
        self.manage_rules_window = ManageRulesWindow(self.rules, self)
        self.manage_rules_window.show()
        self.hide()  # Hide the main window when managing rules

    def show_dashboard(self):
        self.dashboard_window = DashboardWindow(self)  # Pass the main window reference
        self.dashboard_window.show()
        self.hide()  # Hide the main window when viewing the dashboard


class ManageRulesWindow(QMainWindow):
    def __init__(self, rules, main_window):
        super().__init__()
        self.resize(800, 600)
        self.setWindowTitle("Manage Rules")
        self.rules = rules
        self.main_window = main_window

        # Layout
        layout = QVBoxLayout()

        # Add Table
        self.table = QTableWidget()
        self.table.setRowCount(len(rules))
        self.table.setColumnCount(5)  # Updated column count to 5
        self.table.setHorizontalHeaderLabels(
            ["Source IP", "Destination IP", "Protocol", "Action", "View Packets"])  # Updated headers

        # Populate the table with rules
        for i, rule in enumerate(rules):
            self.table.setItem(i, 0, QTableWidgetItem(rule["src_ip"]))
            self.table.setItem(i, 1, QTableWidgetItem(rule["dest_ip"]))
            self.table.setItem(i, 2, QTableWidgetItem(rule["protocol"]))
            self.table.setItem(i, 3, QTableWidgetItem(rule["action"]))

            # Add the 'View Packets' button
            btn_view_packets = QPushButton("View Packets")
            btn_view_packets.clicked.connect(lambda _, r=rule: self.view_packets(r))  # Pass the rule to the function
            self.table.setCellWidget(i, 4, btn_view_packets)  # Place the button in the 5th column (index 4)

        layout.addWidget(self.table)

        # Add buttons to add, edit, delete rules
        self.btn_add_rule = QPushButton("Add Rule")
        self.btn_edit_rule = QPushButton("Edit Rule")
        self.btn_delete_rule = QPushButton("Delete Rule")

        self.btn_add_rule.clicked.connect(self.add_rule)
        self.btn_edit_rule.clicked.connect(self.edit_rule)
        self.btn_delete_rule.clicked.connect(self.delete_rule)

        layout.addWidget(self.btn_add_rule)
        layout.addWidget(self.btn_edit_rule)
        layout.addWidget(self.btn_delete_rule)

        # Add back button
        self.btn_back = QPushButton("Back to Menu")
        self.btn_back.clicked.connect(self.back_to_menu)
        layout.addWidget(self.btn_back)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

    def add_rule(self):
        dialog = AddEditRuleDialog()
        if dialog.exec():
            new_rule = dialog.get_data()
            self.rules.append(new_rule)
            self.refresh_table()

    def edit_rule(self):
        selected_row = self.table.currentRow()
        if selected_row >= 0:
            rule = self.rules[selected_row]
            dialog = AddEditRuleDialog(rule)
            if dialog.exec():
                updated_rule = dialog.get_data()
                self.rules[selected_row] = updated_rule
                self.refresh_table()

    def delete_rule(self):
        selected_row = self.table.currentRow()
        if selected_row >= 0:
            del self.rules[selected_row]
            self.refresh_table()

    def refresh_table(self):
        self.table.setRowCount(len(self.rules))
        for i, rule in enumerate(self.rules):
            self.table.setItem(i, 0, QTableWidgetItem(rule["src_ip"]))
            self.table.setItem(i, 1, QTableWidgetItem(rule["dest_ip"]))
            self.table.setItem(i, 2, QTableWidgetItem(rule["protocol"]))
            self.table.setItem(i, 3, QTableWidgetItem(rule["action"]))

            # Add the 'View Packets' button
            btn_view_packets = QPushButton("View Packets")
            btn_view_packets.clicked.connect(lambda _, r=rule: self.view_packets(r))  # Pass the rule to the function
            self.table.setCellWidget(i, 4, btn_view_packets)  # Place the button in the 5th column (index 4)

    def view_packets(self, rule):
        """Retrieve and display packets that match the rule from MongoDB."""
        # Connect to MongoDB
        client = MongoDbClient()
        db = client.client[DBNames.ALL_PACKETS]  # Replace with your actual database name
        packets_collection = db[Collections.PACKETS]  # Replace with your collection name

        # Query MongoDB based on the rule's source IP, destination IP, and protocol
        query = {
            "src_ip": rule["src_ip"],
            "dest_ip": rule["dest_ip"],
            "protocol": rule["protocol"]
        }
        print(query)
        matching_packets = list(packets_collection.find(query))

        # Create a dialog to display matching packets
        dialog = QDialog(self)
        dialog.setWindowTitle("Matching Packets")
        layout = QVBoxLayout()

        # Table to display packets
        packet_table = QTableWidget()
        packet_table.setRowCount(len(matching_packets))
        packet_table.setColumnCount(4)
        packet_table.setHorizontalHeaderLabels(["Source IP", "Destination IP", "Protocol", "Action"])

        for i, packet in enumerate(matching_packets):
            packet_table.setItem(i, 0, QTableWidgetItem(packet.get("src_ip", "")))
            packet_table.setItem(i, 1, QTableWidgetItem(packet.get("dest_ip", "")))
            packet_table.setItem(i, 2, QTableWidgetItem(packet.get("protocol", "")))
            packet_table.setItem(i, 3, QTableWidgetItem(packet.get("action", "")))

        layout.addWidget(packet_table)
        dialog.setLayout(layout)
        dialog.exec_()

    def back_to_menu(self):
        """Close the current window and go back to the main menu."""
        self.close()
        self.main_window.show()


class AddEditRuleDialog(QDialog):
    def __init__(self, rule=None):
        super().__init__()

        self.setWindowTitle("Add/Edit Rule")
        self.layout = QFormLayout()

        self.src_ip = QLineEdit()
        self.dest_ip = QLineEdit()
        self.protocol = QLineEdit()
        self.action = QLineEdit()

        if rule:
            self.src_ip.setText(rule["src_ip"])
            self.dest_ip.setText(rule["dest_ip"])
            self.protocol.setText(rule["protocol"])
            self.action.setText(rule["action"])

        self.layout.addRow("Source IP:", self.src_ip)
        self.layout.addRow("Destination IP:", self.dest_ip)
        self.layout.addRow("Protocol:", self.protocol)
        self.layout.addRow("Action:", self.action)

        # Dialog Buttons
        self.buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)

        self.layout.addWidget(self.buttons)
        self.setLayout(self.layout)

    def get_data(self):
        return {
            "src_ip": self.src_ip.text(),
            "dest_ip": self.dest_ip.text(),
            "protocol": self.protocol.text(),
            "action": self.action.text(),
        }


class DashboardWindow(QMainWindow):
    def __init__(self, main_window):
        super().__init__()
        self.resize(800, 600)
        self.setWindowTitle("Dashboard")
        self.main_window = main_window

        layout = QVBoxLayout()

        layout.addWidget(QLabel("Packets Protocols Distribution"))

        # Display Pie Charts
        self.display_pie_charts(layout)

        # Back Button
        self.btn_back = QPushButton("Back to Menu")
        self.btn_back.clicked.connect(self.back_to_menu)
        layout.addWidget(self.btn_back)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

    def display_pie_charts(self, layout):
        """Fetch data from MongoDB and display pie charts."""
        mongo_client = MongoDbClient().client
        db = mongo_client[DBNames.ALL_PACKETS]
        collection = db[Collections.PACKETS]

        # Get data for "IN" packets
        in_data = self.get_packet_protocol_distribution(collection, "IN")
        out_data = self.get_packet_protocol_distribution(collection, "OUT")

        # Create pie chart for "IN" packets
        in_figure = self.create_pie_chart(in_data, "IN Packets Protocol Distribution")
        in_canvas = FigureCanvas(in_figure)
        layout.addWidget(in_canvas)

        # Create pie chart for "OUT" packets
        out_figure = self.create_pie_chart(out_data, "OUT Packets Protocol Distribution")
        out_canvas = FigureCanvas(out_figure)
        layout.addWidget(out_canvas)

    def get_packet_protocol_distribution(self, collection, direction):
        """Query MongoDB to get the protocol distribution for given direction."""
        pipeline = [
            {"$match": {"direction": direction}},
            {"$group": {"_id": "$protocol", "count": {"$sum": 1}}}
        ]
        results = list(collection.aggregate(pipeline))
        data = {result["_id"]: result["count"] for result in results}
        return data

    def create_pie_chart(self, data, title):
        """Create a pie chart for the protocol distribution."""
        labels = data.keys()
        sizes = data.values()
        figure, ax = plt.subplots()
        ax.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90)
        ax.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.
        ax.set_title(title)
        return figure

    def back_to_menu(self):
        """Close the current window and go back to the main menu."""
        self.close()
        self.main_window.show()


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = NetworkScanner()
    window.show()
    sys.exit(app.exec_())
