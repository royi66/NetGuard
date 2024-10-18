
class DBNames:
    NET_GUARD_DB = 'net_guard_db'


class Collections:
    PACKETS = 'all_packets'
    RULES = 'rules'


class Ui:
    HOURS_BACK = 4
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

