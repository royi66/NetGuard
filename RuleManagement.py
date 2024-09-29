class Rule:
    """Represents a firewall rule with matching criteria and an action (allow or block)."""

    def __init__(self, src_ip=None, dest_ip=None, src_port=None, dest_port=None, protocol=None, action='block'):
        """
        Initialize the Rule object with optional filtering criteria.

        :param src_ip: Source IP address to match (default: None).
        :param dest_ip: Destination IP address to match (default: None).
        :param src_port: Source port to match (default: None).
        :param dest_port: Destination port to match (default: None).
        :param protocol: Protocol to match (TCP/UDP) (default: None).
        :param action: Action to take if rule matches (allow/block) (default: 'block').
        """
        self.src_ip = src_ip
        self.dest_ip = dest_ip
        self.src_port = src_port
        self.dest_port = dest_port
        self.protocol = protocol
        self.action = action  # Action to be taken: 'allow' or 'block'

    def matches(self, packet):
        """
        Check if the rule matches the given packet.

        :param packet: The packet to check.
        :return: True if the packet matches the rule, False otherwise.
        """
        return (
                (self.src_ip is None or self.src_ip == packet.src_ip) and
                (self.dest_ip is None or self.dest_ip == packet.dest_ip) and
                (self.src_port is None or self.src_port == packet.src_port) and
                (self.dest_port is None or self.dest_port == packet.dest_port) and
                (self.protocol is None or self.protocol == packet.protocol)
        )


class RuleSet:
    """A collection of rules for packet filtering."""

    def __init__(self):
        """Initialize an empty list of rules."""
        self.rules = []

    def add_rule(self, rule):
        """
        Add a rule to the rule set.

        :param rule: A Rule object to be added to the rules list.
        """
        self.rules.append(rule)

    def check_packet(self, packet):
        """
        Check a packet against all rules in the rule set.

        :param packet: The packet to check.
        :return: The action (allow/block) based on the first matching rule, or block by default.
        """
        for rule in self.rules:
            if rule.matches(packet):
                return rule.action  # Return the action if a rule matches
        return 'block'  # Default action is to block if no rule matches
