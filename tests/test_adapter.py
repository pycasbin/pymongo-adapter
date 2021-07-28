from casbin_pymongo_adapter.adapter import Adapter
from casbin_pymongo_adapter.adapter import CasbinRule
from pymongo import MongoClient
from unittest import TestCase
import casbin
import os


def get_fixture(path):
    """
    get model path
    """
    dir_path = os.path.split(os.path.realpath(__file__))[0] + "/"
    return os.path.abspath(dir_path + path)


def get_enforcer():
    adapter = Adapter("mongodb://localhost:27017", "casbin_test")
    e = casbin.Enforcer(get_fixture("rbac_model.conf"), adapter)
    model = e.get_model()

    model.clear_policy()
    model.add_policy("p", "p", ["alice", "data1", "read"])
    adapter.save_policy(model)

    model.clear_policy()
    model.add_policy("p", "p", ["bob", "data2", "write"])
    adapter.save_policy(model)

    model.clear_policy()
    model.add_policy("p", "p", ["data2_admin", "data2", "read"])
    adapter.save_policy(model)

    model.clear_policy()
    model.add_policy("p", "p", ["data2_admin", "data2", "write"])
    adapter.save_policy(model)

    model.clear_policy()
    model.add_policy("g", "g", ["alice", "data2_admin"])
    adapter.save_policy(model)

    return casbin.Enforcer(get_fixture("rbac_model.conf"), adapter)


def clear_db(dbname):
    client = MongoClient("mongodb://localhost:27017")
    client.drop_database(dbname)


class TestConfig(TestCase):
    """
    unittest
    """

    def setUp(self):
        clear_db("casbin_test")

    def tearDown(self):
        clear_db("casbin_test")

    def test_enforcer_basic(self):
        """
        test policy
        """
        e = get_enforcer()
        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data1", "write"))
        self.assertFalse(e.enforce("bob", "data2", "read"))
        self.assertTrue(e.enforce("bob", "data2", "write"))
        self.assertTrue(e.enforce("alice", "data2", "read"))
        self.assertTrue(e.enforce("alice", "data2", "write"))

    def test_add_policy(self):
        """
        test add_policy
        """
        e = get_enforcer()
        adapter = e.get_adapter()
        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data1", "write"))
        self.assertFalse(e.enforce("bob", "data2", "read"))
        self.assertTrue(e.enforce("bob", "data2", "write"))
        self.assertTrue(e.enforce("alice", "data2", "read"))
        self.assertTrue(e.enforce("alice", "data2", "write"))

        # test add_policy after insert 2 rules
        adapter.add_policy(sec="p", ptype="p", rule=("alice", "data1", "write"))
        adapter.add_policy(sec="p", ptype="p", rule=("bob", "data2", "read"))

        # reload policies from database
        e.load_policy()

        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertTrue(e.enforce("alice", "data1", "write"))
        self.assertTrue(e.enforce("bob", "data2", "read"))
        self.assertTrue(e.enforce("bob", "data2", "write"))
        self.assertTrue(e.enforce("alice", "data2", "read"))
        self.assertTrue(e.enforce("alice", "data2", "write"))

    def test_remove_policy(self):
        """
        test remove_policy
        """
        e = get_enforcer()
        adapter = e.get_adapter()
        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data1", "write"))
        self.assertFalse(e.enforce("bob", "data2", "read"))
        self.assertTrue(e.enforce("bob", "data2", "write"))
        self.assertTrue(e.enforce("alice", "data2", "read"))
        self.assertTrue(e.enforce("alice", "data2", "write"))

        # test remove_policy after delete a role definition
        result = adapter.remove_policy(
            sec="g", ptype="g", rule=("alice", "data2_admin")
        )

        # reload policies from database
        e.load_policy()

        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data1", "write"))
        self.assertFalse(e.enforce("bob", "data2", "read"))
        self.assertTrue(e.enforce("bob", "data2", "write"))
        self.assertFalse(e.enforce("alice", "data2", "read"))
        self.assertFalse(e.enforce("alice", "data2", "write"))
        self.assertTrue(result)

    def test_remove_policy_no_remove_when_rule_is_incomplete(self):
        adapter = Adapter("mongodb://localhost:27017", "casbin_test")
        e = casbin.Enforcer(get_fixture("rbac_with_resources_roles.conf"), adapter)

        adapter.add_policy(sec="p", ptype="p", rule=("alice", "data1", "write"))
        adapter.add_policy(sec="p", ptype="p", rule=("alice", "data1", "read"))
        adapter.add_policy(sec="p", ptype="p", rule=("bob", "data2", "read"))
        adapter.add_policy(
            sec="p", ptype="p", rule=("data_group_admin", "data_group", "write")
        )
        adapter.add_policy(sec="g", ptype="g", rule=("alice", "data_group_admin"))
        adapter.add_policy(sec="g", ptype="g2", rule=("data2", "data_group"))

        e.load_policy()

        self.assertTrue(e.enforce("alice", "data1", "write"))
        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertTrue(e.enforce("bob", "data2", "read"))
        self.assertTrue(e.enforce("alice", "data2", "write"))

        # test remove_policy doesn't remove when given an incomplete policy
        result = adapter.remove_policy(sec="p", ptype="p", rule=("alice", "data1"))
        e.load_policy()

        self.assertTrue(e.enforce("alice", "data1", "write"))
        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertTrue(e.enforce("bob", "data2", "read"))
        self.assertTrue(e.enforce("alice", "data2", "write"))
        self.assertFalse(result)

    def test_save_policy(self):
        """
        test save_policy
        """

        e = get_enforcer()
        self.assertFalse(e.enforce("alice", "data4", "read"))

        model = e.get_model()
        model.clear_policy()

        model.add_policy("p", "p", ("alice", "data4", "read"))

        adapter = e.get_adapter()
        adapter.save_policy(model)

        self.assertTrue(e.enforce("alice", "data4", "read"))

    def test_remove_filtered_policy(self):
        """
        test remove_filtered_policy
        """
        e = get_enforcer()
        adapter = e.get_adapter()
        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data1", "write"))
        self.assertFalse(e.enforce("bob", "data2", "read"))
        self.assertTrue(e.enforce("bob", "data2", "write"))
        self.assertTrue(e.enforce("alice", "data2", "read"))
        self.assertTrue(e.enforce("alice", "data2", "write"))

        result = adapter.remove_filtered_policy("g", "g", 6, "alice", "data2_admin")
        e.load_policy()
        self.assertFalse(result)

        result = adapter.remove_filtered_policy(
            "g", "g", 0, *[f"v{i}" for i in range(7)]
        )
        e.load_policy()
        self.assertFalse(result)

        result = adapter.remove_filtered_policy("g", "g", 0, "alice", "data2_admin")
        e.load_policy()
        self.assertTrue(result)
        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data1", "write"))
        self.assertFalse(e.enforce("bob", "data2", "read"))
        self.assertTrue(e.enforce("bob", "data2", "write"))
        self.assertFalse(e.enforce("alice", "data2", "read"))
        self.assertFalse(e.enforce("alice", "data2", "write"))

    def test_str(self):
        """
        test __str__ function
        """
        rule = CasbinRule(ptype="p", v0="alice", v1="data1", v2="read")
        self.assertEqual(rule.__str__(), "p, alice, data1, read")

    def test_dict(self):
        """
        test __str__ function
        """
        rule = CasbinRule(ptype="p", v0="alice", v1="data1", v2="read")
        self.assertEqual(
            rule.dict(), {"ptype": "p", "v0": "alice", "v1": "data1", "v2": "read"}
        )

    def test_repr(self):
        """
        test __repr__ function
        """
        adapter = Adapter("mongodb://localhost:27017", "casbin_test")
        rule = CasbinRule(ptype="p", v0="alice", v1="data1", v2="read")
        self.assertEqual(repr(rule), '<CasbinRule :"p, alice, data1, read">')
        # adapter.save_policy(rule)
        # self.assertRegex(repr(rule), r'<CasbinRule :"p, alice, data1, read">')
