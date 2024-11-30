from pymongo import MongoClient, errors
from datetime import datetime
from bson import ObjectId
from consts import TYPES
from backend.logging_config import logger
from datetime import timedelta, datetime
from consts import FIELDS


class MongoDbClient:
    def __init__(self):
        try:
            self.client = MongoClient('mongodb://localhost:27017/')
            logger.info("MongoDB connection established successfully.")
        except errors.ConnectionFailure as e:
            logger.error(f"Failed to connect to MongoDB: {e}")
            raise e  # Raise the exception after logging the error

    def insert_to_db(self, db_name: str, collection_name: str, document: dict):
        try:
            document["insertion_time"] = datetime.now()
            db = self.client[db_name]
            collection = db[collection_name]
            collection.insert_one(document)
            logger.info("Document inserted successfully")
        except Exception as e:
            logger.error(f"Error inserting document: {e}")
            raise e

    def update_in_db(self, db_name: str, collection_name: str, query: dict, update: dict):
        try:
            db = self.client[db_name]
            collection = db[collection_name]
            result = collection.update_one(query, {'$set': update})
            if result.matched_count > 0:
                logger.info("Document updated successfully.")
            else:
                logger.warning("No document matched the query.")
        except Exception as e:
            logger.error(f"Error updating document: {e}")
            raise e  # Raise the exception after logging the error

    def delete_from_db(self, db_name: str, collection_name: str, query: dict):
        try:
            db = self.client[db_name]
            collection = db[collection_name]
            result = collection.delete_one(query)
            if result.deleted_count > 0:
                logger.info("Document deleted successfully.")
            else:
                logger.warning("No document matched the query.")
        except Exception as e:
            logger.error(f"Error deleting document: {e}")
            raise e

    def find_max_rule_id(self, db_name: str, collection_name: str):
        try:
            db = self.client[db_name]
            collection = db[collection_name]
            max_rule = collection.find_one(sort=[("rule_id", -1)])
            logger.info(f"Max rule found: {max_rule}")
            return max_rule['rule_id'] if max_rule else 0  # Return 0 if no rules exist
        except Exception as e:
            logger.error(f"Error finding max rule id: {e}")
            raise e

    def clear_collection(self, db_name: str, collection_name: str):
        """
        Clear all documents from the specified collection.

        :param db_name: The name of the database.
        :param collection_name: The name of the collection to clear.
        """
        try:
            db = self.client[db_name]
            packets_collection = db[collection_name]
            result = packets_collection.delete_many({})  # Deletes all documents in the collection
            logger.info(f"Deleted {result.deleted_count} documents from the collection.")
        except Exception as e:
            logger.error(f"Error clearing collection: {e}")
            raise e  # Raise the exception after logging the error

    def get_data_by_field(self, db_name: str, collection_name: str, field: str, value, return_type="list"):
        try:
            db = self.client[db_name]
            collection = db[collection_name]

            if field == FIELDS.ID:
                return self.find_by_id(db_name, collection_name, value)
            else:
                if field in TYPES.INTEGER_VALUES_IN_DB:
                    value = int(value)
                if field in TYPES.UPPER_CASE_VALUES:
                    value = value.upper()
                query = {field: value}
                result = collection.find(query)
                if return_type == "list":
                    return list(result)
                return result
        except Exception as e:
            logger.error(f"Error fetching data by field '{field}': {e}")
            raise e

    def find_by_id(self, db_name: str, collection_name: str, packet_id: str):
        try:
            db = self.client[db_name]
            packets_collection = db[collection_name]

            packet = packets_collection.find_one({"_id": ObjectId(packet_id)})
            if packet:
                logger.info(f"Found packet with id {packet_id}")
                return packet
            else:
                return None
        except Exception as e:
            logger.error(f"Error while retrieving packet: {e}")
            raise e

    def close_connection(self):
        """Close the MongoDB connection."""
        try:
            self.client.close()
            logger.info("MongoDB connection closed successfully.")
        except Exception as e:
            logger.error(f"Error closing MongoDB connection: {e}")
            raise e  # Raise the exception after logging the error

    def anomaly_query(self, db_name: str, collection_name: str, pipeline: list):
        """
        Executes a custom aggregation pipeline to detect anomalies in MongoDB.

        :param db_name: The name of the database.
        :param collection_name: The name of the collection to query.
        :param pipeline: The aggregation pipeline for the anomaly detection query.
        :return: List of documents that meet the anomaly condition.
        """
        try:
            db = self.client[db_name]
            collection = db[collection_name]
            results = list(collection.aggregate(pipeline))
            if results:
                logger.info(f"Anomalies detected: {results}")
            else:
                logger.info("No anomalies detected.")

            return results  # Returns list of documents that match the anomaly condition
        except Exception as e:
            logger.error(f"Error running anomaly query: {e}")
            raise e

    def get_all_documents(self, db_name, collection_name):
        """Retrieve all documents from a specified collection in the database."""
        try:
            db = self.client[db_name]
            collection = db[collection_name]
            documents = list(collection.find())
            return documents
        except Exception as e:
            logger.error(f"Error retrieving documents from {collection_name}: {e}")
            return []

    def get_data_counter_in_timedelta(self, db_name, collection_name, time_back, time_field_name):
        try:
            db = self.client[db_name]
            collection = db[collection_name]
            count = collection.count_documents(
                {time_field_name: {"$gte": datetime.now() - timedelta(hours=time_back)}}
            )
            return count
        except Exception as e:
            logger.error(f"Error in get_data_counter_in_timedelta: {e}")
            return None

    def get_data_time_back(self, db_name, collection_name, time_back, time_field_name, skip, page_size, sort_field=None,
                           sort_order=1):
        try:
            db = self.client[db_name]
            collection = db[collection_name]
            query = {time_field_name: {"$gte": time_back}}
            if sort_field:
                cursor = collection.find(query).sort(sort_field, sort_order).skip(skip).limit(page_size)
            else:
                cursor = collection.find(query).skip(skip).limit(page_size)

            return list(cursor)

        except Exception as e:
            logger.error(f"Error in get_data_time_back: {e}")
            return None

    def has_more_recent_packets(self, db_name, collection_name, skip, page_size, time_back, time_field_name):
        """
        Checks if there are more packets in the collection that were inserted in the last hour
        beyond the current page.

        Args:
            packets_collection (Collection): The MongoDB collection containing the packets.
            skip (int): The number of documents to skip, typically calculated for pagination.
            page_size (int): The number of packets displayed per page.

        Returns:
            bool: True if there are more recent packets beyond the current page, False otherwise.
        """
        db = self.client[db_name]
        collection = db[collection_name]
        query = {time_field_name: {"$gte": time_back}}

        total_matching_packets = collection.count_documents(query)

        return total_matching_packets > (skip + page_size)


