import casbin
from casbin import persist
import pymongo

class CasbinRule():
    '''
    CasbinRule model
    '''

    __tablename__ = "casbin_rule"

    def __init__(self, ptype, v0, v1, v2, v3, v4, v5, v6):
        self.ptype = ptype
        self.v0 = v0
        self.v1 = v1
        self.v2 = v2
        self.v3 = v3
        self.v4 = v4
        self.v5 = v5
        self.v6 = v6
    
        for v in (self.ptype, self.v0, self.v1, self.v2, self.v3, self.v4, self.v5, self.v6):
            if len(v) > 255:
                self.error("String value is too long")

    def __str__(self):
        text = self.ptype
        if self.v0:
            text = text+', '+self.v0
        if self.v1:
            text = text+', '+self.v1
        if self.v2:
            text = text+', '+self.v2
        if self.v3:
            text = text+', '+self.v3
        if self.v4:
            text = text+', '+self.v4
        if self.v5:
            text = text+', '+self.v5
        if self.v6:
            text = text+', '+self.v6

        return text

    def __repr__(self):
        return '<CasbinRule :"{}">'.format(str(self))


class Adapter(persist.Adapter):
    """the interface for Casbin adapters."""

    def __init__(self,dbname,host):
        self.dbname = dbname
        self.host = host
        self.client = pymongo.MongoClient(host=self.host)
        self.db = self.client[dbname]

    def load_policy(self, model):
        '''
        implementing add Interface for casbin \n
        load all policy rules from mongodb \n
        '''
        lines = CasbinRule.objects()
        for line in lines:
            persist.load_policy_line(str(line),model)

    def _save_policy_line(self, ptype, rule):
        line = CasbinRule()
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
        line.save()

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
    