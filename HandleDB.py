from pymongo import MongoClient
from datetime import datetime
import typing


class MongoDbClient:
    def __init__(self):
        self.client = MongoClient('mongodb://localhost:27017/')

    def insert_to_db(self, db_name: str, collection_name: str, packet: dict):
        db = self.client[db_name]
        packets_collection = db[collection_name]
        packets_collection.insert_one(packet)

    def __del__(self) -> None:
        self.client.close()