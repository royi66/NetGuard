import threading
import time
from backend.handle_db import MongoDbClient
from backend.logging_config import logger
from datetime import datetime, timedelta
from consts import Collections, DBNames, FIELDS


def high_traffic_on_any_port_anomaly(threshold=2):
    anomaly_name = "high_traffic_on_any_port"
    one_minute_ago = datetime.now() - timedelta(minutes=1)
    return anomaly_name, [
        {"$match": {"insertion_time": {"$gte": one_minute_ago}}},  # Filter for last minute
        {"$group": {"_id": "$dest_port", "packetCount": {"$sum": 1}}},  # Group by each destination port
        {"$match": {"packetCount": {"$gte": threshold}}},  # Only ports with >= threshold packets
        {"$sort": {"packetCount": -1}}  # Sort by packet count for easier analysis
    ]


def high_distinct_destinations_anomaly(threshold=10):
    anomaly_name = "high_distinct_destinations_anomaly"
    one_minute_ago = datetime.now() - timedelta(minutes=1)
    return anomaly_name, [
        {"$match": {"insertion_time": {"$gte": one_minute_ago}}},
        {"$group": {"_id": "$src_ip", "distinctDestinations": {"$addToSet": "$dest_ip"}}},
        {"$project": {"_id": 1, "distinctDestinationsCount": {"$size": "$distinctDestinations"}}},
        {"$match": {"distinctDestinationsCount": {"$gte": threshold}}},
        {"$sort": {"distinctDestinationsCount": -1}}
    ]


def packets_from_same_ip_anomaly(threshold=2):
    anomaly_name = "packets_from_same_ip_anomaly"
    one_minute_ago = datetime.now() - timedelta(minutes=1)
    return anomaly_name, [
        {"$match": {"insertion_time": {"$gte": one_minute_ago}}},  # Filter for last minute
        {"$group": {"_id": "$src_ip", "packetCount": {"$sum": 1}}},  # Group by IP, count packets
        {"$match": {"packetCount": {"$gte": threshold}}},  # Only IPs with >= threshold packets
        {"$sort": {"packetCount": -1}}
    ]


class AnomalyDetector:
    def __init__(self, db_client: MongoDbClient, db_name=DBNames.NET_GUARD_DB, collection_name=Collections.ANOMALIES):
        self.db_client = db_client
        self.db_name = db_name
        self.collection_name = collection_name
        self.anomalies = [packets_from_same_ip_anomaly, high_traffic_on_any_port_anomaly,
                          high_distinct_destinations_anomaly]

    def check_for_anomalies(self):
        """Periodically check for anomalies in the packet data."""
        while True:
            for anomaly_func in self.anomalies:
                anomaly_name, anomaly_pipline = anomaly_func()
                anomaly_result = self.db_client.anomaly_query(self.db_name, Collections.PACKETS, anomaly_pipline)
                if anomaly_result:  # Each condition checks the DB independently
                    self.save_anomaly_result(anomaly_name, anomaly_result)
            time.sleep(10)  # Adjust frequency as needed

    def save_anomaly_result(self, anomaly_name, anomaly_result):
        logger.info(f"Anomaly detected: {anomaly_result}")
        anomaly_dict = {FIELDS.ANOMALY_NAME: anomaly_name, FIELDS.ANOMALY_TIME: datetime.now(),
                        FIELDS.ANOMALY_RESULT: anomaly_result}
        self.db_client.insert_to_db(self.db_name, self.collection_name, anomaly_dict)
