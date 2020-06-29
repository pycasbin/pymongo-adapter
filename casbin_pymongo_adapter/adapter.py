import casbin
from casbin import persist
from pymongo import MongoClient

class CasbinRule():
    '''
    CasbinRule model
    '''

    __tablename__ = "casbin_rule"

    def __init__(self, ptype='', v0='', v1='', v2='', v3='', v4='', v5=''):
        self.ptype = ptype
        self.v0 = v0
        self.v1 = v1
        self.v2 = v2
        self.v3 = v3
        self.v4 = v4
        self.v5 = v5

    def __str__(self):
        dict = {'ptype':self.ptype}
        if self.v0:
            dict['v0'] = self.v0
        if self.v1:
            dict['v1'] = self.v1
        if self.v2:
            dict['v2'] = self.v2
        if self.v3:
            dict['v3'] = self.v3
        if self.v4:
            dict['v4'] = self.v4
        if self.v5:
            dict['v5'] = self.v5
        return dict

    def __repr__(self):
        return '<CasbinRule :"{}">'.format(str(self))


class Adapter(persist.Adapter):
    """the interface for Casbin adapters."""

    def __init__(self, uri, dbname, collection="casbin_rule"):
        client = MongoClient(uri)
        db = client[dbname]
        self._collection = db[collection]

    def load_policy(self, model):
        '''
        implementing add Interface for casbin \n
        load all policy rules from mongodb \n
        '''
        for lines in self._collection.find():
            persist.load_policy_line(str(lines), model)

    def _save_policy_line(self, ptype, rule):
        line = CasbinRule(ptype=ptype)
        if len(rule) > 0:
            line.v0 = rule[0]
        if len(rule) > 1:
            line.v1 = rule[1]
        if len(rule) > 2:
            line.v2 = rule[2]
        if len(rule) > 3:
            line.v3 = rule[3]
        if len(rule) > 4:
            line.v4 = rule[4]
        if len(rule) > 5:
            line.v5 = rule[5]
        self._collection.insert_one(line.__str__())

    def save_policy(self, model):
        '''
        implementing add Interface for casbin \n
        save the policy in mongodb \n
        '''
        for sec in ["p", "g"]:
            if sec not in model.model.keys():
                continue
            for ptype, ast in model.model[sec].items():
                for rule in ast.policy:
                    self._save_policy_line(ptype, rule)
        return True

    def add_policy(self, sec, ptype, rule):
        """add policy rules to mongodb"""
        self._save_policy_line(ptype, rule)

    def remove_policy(self, sec, ptype, rule):
        """delete policy rules from mongodb"""
        pass

    def remove_filtered_policy(self, sec, ptype, field_index, *field_values):
        """
        delete policy rules for matching filters from mongodb
        """
        pass
