from casbin_pymongo_adapter.adapter import Adapter
from casbin_pymongo_adapter.adapter import CasbinRule
from unittest import TestCase
import casbin
import os


def get_fixture(path):
    '''
    get model path
    '''
    dir_path = os.path.split(os.path.realpath(__file__))[0] + "/"
    return os.path.abspath(dir_path + path)


def get_enforcer():
    adapter = Adapter('mongodb://localhost:27017', 'casbin_test')

    e = casbin.Enforcer(get_fixture('rbac_model.conf'), adapter)
    model = e.get_model()
    model.clear_policy()
    model.add_policy('p', 'p', ['alice', 'data1', 'read'])
    adapter.save_policy(model)

    model.clear_policy()
    model.add_policy('p', 'p', ['bob', 'data2', 'write'])
    adapter.save_policy(model)

    model.clear_policy()
    model.add_policy('p', 'p', ['data2_admin', 'data2', 'read'])
    adapter.save_policy(model)

    model.clear_policy()
    model.add_policy('p', 'p', ['data2_admin', 'data2', 'write'])
    adapter.save_policy(model)

    model.clear_policy()
    model.add_policy('g', 'g', ['alice', 'data2_admin'])
    adapter.save_policy(model)

    return casbin.Enforcer(get_fixture('rbac_model.conf'), adapter)


class TestConfig(TestCase):
    '''
    unittest
    '''

    def test_enforcer_basic(self):
        '''
        test policy
        '''
        e = get_enforcer()
        self.assertTrue(e.enforce('alice', 'data1', 'read'))
        self.assertTrue(e.enforce('bob', 'data2', 'write'))
        self.assertTrue(e.enforce('bob', 'data2', 'write'))
        self.assertTrue(e.enforce('alice', 'data2', 'read'))
        self.assertTrue(e.enforce('alice', 'data2', 'write'))

    def test_add_policy(self):
        '''
        test add_policy
        '''
        adapter = Adapter('mongodb://localhost:27017', 'casbin_rule')
        e = casbin.Enforcer(get_fixture('rbac_model.conf'), adapter)

        adapter.add_policy(sec=None, ptype='p', rule=['alice', 'data1', 'read'])
        adapter.add_policy(sec=None, ptype='p', rule=['bob', 'data2', 'write'])
        adapter.add_policy(sec=None, ptype='p', rule=['data2_admin', 'data2', 'read'])
        adapter.add_policy(sec=None, ptype='p', rule=['data2_admin', 'data2', 'write'])
        adapter.add_policy(sec=None, ptype='g', rule=['alice', 'data2_admin'])

        e.load_policy()

        self.assertFalse(e.enforce('alice', 'data1', 'write'))
        self.assertFalse(e.enforce('bob', 'data1', 'read'))
        self.assertTrue(e.enforce('bob', 'data2', 'write'))
        self.assertTrue(e.enforce('alice', 'data2', 'read'))
        self.assertTrue(e.enforce('alice', 'data2', 'write'))
        self.assertFalse(e.enforce('bogus', 'data2', 'write'))

    def test_save_policy(self):
        '''
        test save_policy
        '''

        e = get_enforcer()
        self.assertFalse(e.enforce('alice', 'data4', 'read'))

        model = e.get_model()
        model.clear_policy()

        model.add_policy('p', 'p', ['alice', 'data4', 'read'])

        adapter = e.get_adapter()
        adapter.save_policy(model)

        self.assertTrue(e.enforce('alice', 'data4', 'read'))

    def test_str(self):
        '''
        test __str__ function
        '''
        rule = CasbinRule(ptype='p', v0='alice', v1='data1', v2='read')
        self.assertEqual(rule.__str__(), 'p, alice, data1, read')

    def test_dict(self):
        '''
        test __str__ function
        '''
        rule = CasbinRule(ptype='p', v0='alice', v1='data1', v2='read')
        self.assertEqual(rule.dict(), {"ptype": 'p', "v0": 'alice', "v1": 'data1', "v2": 'read'})

    def test_repr(self):
        '''
        test __repr__ function
        '''
        adapter = Adapter('mongodb://localhost:27017', 'casbin_test')
        rule = CasbinRule(ptype='p', v0='alice', v1='data1', v2='read')
        self.assertEqual(repr(rule), '<CasbinRule :"p, alice, data1, read">')
        # adapter.save_policy(rule)
        # self.assertRegex(repr(rule), r'<CasbinRule :"p, alice, data1, read">')