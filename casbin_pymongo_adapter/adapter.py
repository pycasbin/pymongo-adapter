import casbin
from casbin import persist
from pymongo import MongoClient

class CasbinRule:
    '''
    CasbinRule model
    '''

    def __init__(self, ptype = None, v0 = None, v1 = None, v2 = None, v3 = None, v4 = None, v5 = None):
        self.ptype = ptype
        self.v0 = v0
        self.v1 = v1
        self.v2 = v2
        self.v3 = v3
        self.v4 = v4
        self.v5 = v5

    def dict(self):
        d = {'ptype': self.ptype}

        for i, v in enumerate([self.v0, self.v1, self.v2, self.v3, self.v4, self.v5]):
            if v is None:
                break
            d['v' + str(i)] = v

        return d

    def __str__(self):
        return ', '.join(self.dict().values())

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

        for line in self._collection.find():
            if 'ptype' not in line:
                continue

            rule = CasbinRule(line['ptype'])
            if 'v0' in line:
                rule.v0 = line['v0']
            if 'v1' in line:
                rule.v1 = line['v1']
            if 'v2' in line:
                rule.v2 = line['v2']
            if 'v3' in line:
                rule.v3 = line['v3']
            if 'v4' in line:
                rule.v4 = line['v4']
            if 'v5' in line:
                rule.v5 = line['v5']

            persist.load_policy_line(str(rule), model)

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
        self._collection.insert_one(line.dict())

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
