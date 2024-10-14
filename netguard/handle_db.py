from pymongo import MongoClient
from datetime import datetime
import typing
from bson import ObjectId


class MongoDbClient:
    def __init__(self):
        self.client = MongoClient('mongodb://localhost:27017/')

    def insert_to_db(self, db_name: str, collection_name: str, document: dict):
        document["insertion_time"] = datetime.now()
        db = self.client[db_name]
        collection = db[collection_name]
        collection.insert_one(document)

    def update_in_db(self, db_name: str, collection_name: str, query: dict, update: dict):
        # TODO - does not let an option to change packets db
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

    def get_data_by_field(self, db_name: str, collection_name: str, field: str, value):
        # Connect to MongoDB
        client = MongoClient()
        db = client[db_name]
        collection = db[collection_name]

        if field == "_id":
            return self.find_by_id(db_name, collection_name, value)
        else:
            query = {field: value}

            result = collection.find(query)

            return list(result)

    def find_by_id(self, db_name: str, collection_name: str, packet_id: str):
        db = self.client[db_name]
        packets_collection = db[collection_name]

        try:
            # Find the document by ObjectId
            packet = packets_collection.find_one({"_id": ObjectId(packet_id)})
            if packet:
                return packet  # Return the found document
            else:
                return None  # Return None if no document is found
        except Exception as e:
            print(f"Error while retrieving packet: {e}")
            return None  # Handle any exceptions and return None

