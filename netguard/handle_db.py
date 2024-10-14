from pymongo import MongoClient
from datetime import datetime
import typing


class MongoDbClient:
    def __init__(self):
        self.client = MongoClient('mongodb://localhost:27017/')

    def insert_to_db(self, db_name: str, collection_name: str, document: dict):
        db = self.client[db_name]
        collection = db[collection_name]
        collection.insert_one(document)

    def update_in_db(self, db_name: str, collection_name: str, query: dict, update: dict):
        db = self.client[db_name]
        collection = db[collection_name]
        collection.update_one(query, {'$set': update})

    def delete_from_db(self, db_name: str, collection_name: str, query: dict):
        db = self.client[db_name]
        collection = db[collection_name]
        collection.delete_one(query)

    def find_max_rule_id(self, db_name: str, collection_name: str):
        db = self.client[db_name]
        collection = db[collection_name]
        max_rule = collection.find_one(sort=[("rule_id", -1)])
        return max_rule['rule_id'] if max_rule else 0  # Return 0 if no rules exist

    def clear_collection(self, db_name: str, collection_name: str):
        """
        Clear all documents from the specified collection.

        :param db_name: The name of the database.
        :param collection_name: The name of the collection to clear.
        """
        db = self.client[db_name]
        packets_collection = db[collection_name]
        packets_collection.delete_many({})  # Deletes all documents in the collection