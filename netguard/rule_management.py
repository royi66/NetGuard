import typing
from pymongo import MongoClient
from scapy.all import IP

from utils import singleton
from handle_db import MongoDbClient
from consts import DBNames, Collections, FIELDS, ERROR_CODE
import threading


class Rule:
    """Represents a Scanner rule with matching criteria and an action (allow or block)."""

    def __init__(self, rule_id: int, src_ip: str = None, dest_ip: str = None,
                 src_port: int = None, dest_port: int = None, protocol: str = None,
                 action: str = 'block', ttl: int = None, checksum: int = None, tcp_flags: str = None,
                 alert: bool =False) -> None:
        """
        Initialize the Rule object with optional filtering criteria.

        :param rule_id: Unique identifier for the rule.
        :param src_ip: Source IP address to match (default: None).
        :param dest_ip: Destination IP address to match (default: None).
        :param src_port: Source port to match (default: None).
        :param dest_port: Destination port to match (default: None).
        :param protocol: Protocol to match (TCP/UDP) (default: None).
        :param action: Action to take if rule matches (allow/block) (default: 'block').
        """
        # TODO - maybe no need of rule id because mongo db automatically adds an id
        self.rule_id: int = rule_id
        self.src_ip: typing.Optional[str] = src_ip
        self.dest_ip: typing.Optional[str] = dest_ip
        self.src_port: typing.Optional[int] = src_port
        self.dest_port: typing.Optional[int] = dest_port
        self.protocol: typing.Optional[str] = protocol
        self.ttl = ttl
        self.checksum = checksum
        self.tcp_flags = tcp_flags
        self.action: str = action
        self.alert = alert

    def matches(self, packet) -> bool:
        """Check if the rule matches the given packet."""

        return (
                (self.src_ip is None or ('IP' in packet and packet[IP].src == self.src_ip)) and
                (self.dest_ip is None or ('IP' in packet and packet[IP].dst == self.dest_ip)) and
                (self.src_port is None or hasattr(packet, 'sport') and packet.sport == self.src_port) and
                (self.dest_port is None or hasattr(packet, 'dport') and packet.dport == self.dest_port) and
                (self.protocol is None or hasattr(packet, 'proto') and packet.proto == self.protocol)
        )


def get_rule_dict(rule):
    return {FIELDS.RULE_ID: rule.rule_id, FIELDS.SRC_IP: rule.src_ip, FIELDS.DEST_IP: rule.dest_ip,
            FIELDS.SRC_PORT: rule.src_port, FIELDS.DEST_PORT: rule.dest_port, FIELDS.PROTOCOL: rule.protocol,
            FIELDS.ACTION: rule.action, FIELDS.TTL: rule.ttl, FIELDS.CHECKSUM: rule.checksum,
            FIELDS.TCP_FLAGS: rule.tcp_flags, FIELDS.ALERT: rule.alert}


@singleton
class RuleSet:
    """A singleton collection of rules for packet filtering."""

    def __init__(self, db_client: MongoDbClient,
                 db_name: str = DBNames.NET_GUARD_DB,
                 collection_name: str = Collections.RULES) -> None:
        self.lock: threading.Lock = threading.Lock()
        self.rules: typing.List[Rule] = []
        self.db_client: MongoDbClient = db_client
        self.db_name: str = db_name
        self.collection_name: str = collection_name
        self.load_rules_from_db()
        self.rule_id_counter: int = self.db_client.find_max_rule_id(self.db_name, self.collection_name)

    def load_rules_from_db(self) -> None:
        """Load rules from MongoDB into the ruleset."""
        self.rules = []
        rules_data = self.db_client.client[self.db_name][self.collection_name].find()
        with self.lock:  # Acquire the lock before modifying shared data
            for rule_data in rules_data:
                rule = Rule(
                    rule_id=rule_data[FIELDS.RULE_ID],
                    src_ip=rule_data.get(FIELDS.SRC_IP),
                    dest_ip=rule_data.get(FIELDS.DEST_IP),
                    src_port=rule_data.get(FIELDS.SRC_PORT),
                    dest_port=rule_data.get(FIELDS.DEST_PORT),
                    protocol=rule_data.get(FIELDS.PROTOCOL),
                    alert=rule_data.get(FIELDS.ALERT),
                    action=rule_data.get('action', 'block')
                )
                self.rules.append(rule)

    def add_rule(self, src_ip: str = None, dest_ip: str = None,
                 src_port: int = None, dest_port: int = None,
                 protocol: str = None, action: str = 'block', ttl: int = None,
                 checksum:int = None, tcp_flags:str = None, alert:bool = False) -> None:
        """Add a rule to the rule set and save it to the database.

        :param src_ip: Source IP address to match.
        :param dest_ip: Destination IP address to match.
        :param src_port: Source port to match.
        :param dest_port: Destination port to match.
        :param protocol: Protocol to match (TCP/UDP).
        :param action: Action to take if rule matches (allow/block).
        :param ttl: Time to live of the packet
        :param checksum: The
        :param tcp_flags: Flags in the TCP packet
        :param alert: Does the user wants to get an alert when a packet matches this rule
        """
        # TODO - Create same function that gets a Rule, or maybe change this one
        with self.lock:
            self.rule_id_counter += 1
            rule = Rule(rule_id=self.rule_id_counter, src_ip=src_ip, dest_ip=dest_ip,
                        src_port=src_port, dest_port=dest_port, protocol=protocol, action=action,
                        ttl=ttl, checksum=checksum, tcp_flags=tcp_flags, alert=alert)
            self.rules.append(rule)

            # Save rule to the database
            self.db_client.insert_to_db(self.db_name, self.collection_name, get_rule_dict(rule))
            print(f"Added rule: {rule.rule_id}")

    def delete_rule(self, rule_id: int) -> None:
        """Remove a rule from the rule set by its unique identifier.

        :param rule_id: Unique identifier of the rule to delete.
        """
        with self.lock:  # Acquire the lock before modifying shared data
            self.rules = [rule for rule in self.rules if rule.rule_id != rule_id]
            self.db_client.delete_from_db(self.db_name, self.collection_name, {'rule_id': rule_id})

            # Reset rule ID counter if the deleted rule was the highest ID
            if self.rule_id_counter == rule_id:
                self.rule_id_counter = max((rule.rule_id for rule in self.rules), default=0)
            print(f"Deleted rule with ID: {rule_id}")

    def edit_rule(self, rule_id: int, **kwargs: typing.Any) -> None:
        """Edit an existing rule in the rule set.

        :param rule_id: Unique identifier of the rule to edit.
        :param kwargs: Key-value pairs of attributes to update.
        """
        print("kwargs", kwargs)
        with self.lock:
            for rule in self.rules:
                if rule.rule_id == rule_id:
                    for key, value in kwargs.items():
                        if hasattr(rule, key) and value is not None:
                            setattr(rule, key, value)

                    self.db_client.update_in_db(self.db_name, self.collection_name,
                                                {FIELDS.RULE_ID: rule_id}, kwargs)
                    print(f"Edited rule with ID: {rule_id} to {kwargs}")
                    print("changed??? ", rule.alert)
                    return

            raise ValueError(f"Rule with ID {rule_id} not found")

    def check_packet(self, packet) -> int :
        """Check a packet against all rules in the rule set.

        :param packet: The packet to check against the rules.
        :return: The associated rule id that matched with packet or -1 if didnt match any rule
        """
        with self.lock:  # Acquire the lock before reading shared data
            for rule in self.rules:
                if rule.matches(packet):
                    return rule.rule_id
        # print(f"Packet didn't match any rule: {packet}")
        return ERROR_CODE.RULE_ERROR_ID

    def clear_all_rules(self) -> None:
        """Clear all rules from both the local ruleset and the database."""
        with self.lock:  # Acquire the lock before modifying shared data
            # Clear the rules from the local list
            self.rules.clear()

            # Clear the rules from the database
            self.db_client.clear_collection(self.db_name, self.collection_name)

            # Reset rule ID counter
            self.rule_id_counter = 0
            print("Cleared all rules from the rule set and database.")

    def print_all_rules(self) -> None:
        """Print all rules in a nicely formatted manner."""
        with self.lock:  # Acquire the lock before reading shared data
            if not self.rules:
                print("No rules available.")
                return

            print(f"{'Rule ID':<10} {'Source IP':<20} {'Destination IP':<20} {'Source Port':<15} {'Destination Port':<15} {'Protocol':<10} {'Action':<10}")
            print("=" * 100)  # Separator line

            for rule in self.rules:
                print(f"{rule.rule_id:<10} {rule.src_ip or 'N/A':<20} {rule.dest_ip or 'N/A':<20} {rule.src_port or 'N/A':<15} {rule.dest_port or 'N/A':<15} {rule.protocol or 'N/A':<10} {rule.action:<10}")

    def get_all_rules(self):
        all_rules = []
        with self.lock:
            for rule in self.rules:
                all_rules.append(get_rule_dict(rule))
        return all_rules

    def get_rule_by_id(self, rule_id):
        rule = self.db_client.get_data_by_field(self.db_name, self.collection_name, 'rule_id', rule_id)
        return rule[0]

    def get_all_alerts(self):
        """Retrieve all alerts."""
        alerts_collection = self.db[Collections.ALERTS]
        return list(alerts_collection.find())

