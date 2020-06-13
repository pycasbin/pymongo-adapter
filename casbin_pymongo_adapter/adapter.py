from casbin import persist
from pymongo import MongoClient


class Adapter(persist.Adapter):
    """the pymongo adapter for Casbin."""

    def __init__(self, uri, dbname, collection="casbin_rule"):
        client = MongoClient(uri)
        db = client[dbname]
        self._collection = db[collection]
        pass

    def load_policy(self, model):
        """loads all policy rules from the storage."""
        for lines in self._collection.find():
            pass

    def save_policy(self, model):
        """saves all policy rules to the storage."""
        pass

    def add_policy(self, sec, ptype, rule):
        """adds a policy rule to the storage."""
        pass

    def remove_policy(self, sec, ptype, rule):
        """removes a policy rule from the storage."""
        pass

    def remove_filtered_policy(self, sec, ptype, field_index, *field_values):
        """removes policy rules that match the filter from the storage.
        This is part of the Auto-Save feature.
        """
        pass
