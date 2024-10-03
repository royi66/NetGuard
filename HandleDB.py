from pymongo import MongoClient


def save_packet_to_db(packet_data):
    """Save packet data to MongoDB."""
    client = MongoClient('mongodb://localhost:27017/')  # Connect to MongoDB
    db = client['network_traffic']  # Database name
    collection = db['packets']  # Collection name
    collection.insert_one(packet_data)  # Insert packet data
    client.close()  # Close connection