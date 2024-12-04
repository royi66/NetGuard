
class DBNames:
    NET_GUARD_DB = 'net_guard_db'


class Collections:
    PACKETS = 'all_packets'
    RULES = 'rules'
    ANOMALIES = 'anomalies'


class TYPES:
    INTEGER_VALUES_IN_DB = ['protocol_num', 'ttl', 'length', 'matched_rule_id', 'fragment_offset',
                            'src_port', 'dest_port', 'checksum']
    UPPER_CASE_VALUES = ["direction"]


class ERROR_CODE:
    RULE_ERROR_ID = -1


class FIELDS:
    ID = '_id'
    DIRECTION = 'direction'
    SRC_IP = 'src_ip'
    DEST_IP = 'dest_ip'
    PROTOCOL = 'protocol'
    SRC_PORT = 'src_port'
    DEST_PORT = 'dest_port'
    MATCHED_RULE = 'matched_rule_id'
    ACTION = 'action'
    TTL = 'ttl'
    CHECKSUM = 'checksum'
    TCP_FLAGS = 'tcp_flags'
    INSERTION_TIME = 'insertion_time'
    RULE_ID = 'rule_id'
    ALERT = 'alert'
    ANOMALY_NAME = 'anomaly_name'
    ANOMALY_TIME = 'anomaly_time'
    ANOMALY_RESULT = 'anomaly_result'
    ANOMALY_APPROVED = 'anomaly_approved'


class LABELS:
    SRC_IP = "Source IP"
    DEST_IP = "Destination IP"
    PROTOCOL = "Protocol"
    RULE_ID = "Rule ID"
    ACTION = "Action"
    DIRECTION = "Direction"
    INSERTION_TIME = 'Insertion Time'
    PROTOCOL_NUMBER = "Protocol Number"
    TTL = "TTL"
    PACKET_LENGTH = "Packet Length"
    SRC_PORT = 'Source Port'
    DEST_PORT = 'Destination Port'
    MATCHED_RULE_ID = 'Matched Rule ID'
    FRAGMENT_OFFSET = "Frame Offset"
    MORE_FRAGMENTS = "More Fragments"
    PAYLOAD = 'Payload'


class Ui:
    HOURS_BACK = 2
    PAGE_SIZE = 20
    DARK_MODE_CSS = """
    <style>
    body {
        background-color: #333;
        color: white;
    }
    .markdown, .table, button, div, label, p {
        background-color: #333;
        color: white;
    }
    input, select, textarea {
        background-color: #444;
        color: white;
    }
    .btn {
        background-color: #555;
        border: 1px solid #777;
        color: white;
    }
    table {
        background-color: #333;
        color: white;
        border-collapse: collapse;
        width: 100%;
    }
    th, td {
        border: 1px solid #555;
        padding: 8px;
        text-align: left;
    }
    th {
        background-color: #333;
    }
    td {
        background-color: #333;
    }
    img {
        background-color: #333 !important;
    }

    /* Popup specific styles */
    .popup-content {
        top: 50% !important;
        left: 50% !important;
        transform: translate(-50%, -50%) !important;
        position: fixed !important;
        background-color: #333;
        color: white;
        padding: 20px;
        border-radius: 10px;
        width: 30vw;
        height: auto;
        z-index: 10000;
        box-shadow: 0 0 15px rgba(0, 0, 0, 0.7);
    }
    .popup-backdrop {
        background-color: rgba(0, 0, 0, 0.8);
        position: fixed;
        top: 0;
        left: 0;
        width: 100vw;
        height: 100vh;
        z-index: 9999;
    }

    .popup-input-group {
        margin-bottom: 15px;
    }

    .popup-actions {
        display: flex;
        justify-content: space-between;
    }
</style>
    """


class Paths:
    ICON_URL = 'icon2.png'

class Directions:
    OUT_DIRECTION = "OUT"
    IN_DIRECTION = "IN"
