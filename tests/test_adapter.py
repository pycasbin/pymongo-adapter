from casbin_pymongo_adapter.adapter import Adapter
from casbin_pymongo_adapter.adapter import CasbinRule
from unittest import TestCase
import casbin
import os
import simpleeval

def get_fixture(path):
    '''
    get model path
    '''
    dir_path = os.path.split(os.path.realpath(__file__))[0] + "/"
    return os.path.abspath(dir_path + path)


def get_enforcer():
    adapter = Adapter('mongodb://localhost:27017', 'casbin_test')
    c1 = CasbinRule(ptype='p', v0='alice', v1='data1', v2='read')
    adapter.save_policy(c1)
    c2 = CasbinRule(ptype='p', v0='bob', v1='data2', v2='write')
    adapter.save_policy(c2)
    c3 = CasbinRule(ptype='p', v0='data2_admin', v1='data2', v2='read')
    adapter.save_policy(c3)
    c4 = CasbinRule(ptype='p', v0='data2_admin', v1='data2', v2='write')
    adapter.save_policy(c4)
    c5 = CasbinRule(ptype='g', v0='alice', v1='data2_admin')
    adapter.save_policy(c5)

    return casbin.Enforcer(get_fixture('rbac_model.conf'), adapter, True)


class TestConfig(TestCase):
    '''
    unittest
    '''

    def test_enforcer_basic(self):
        '''
        test policy
        '''
        e = get_enforcer()
        self.assertFalse(e.enforce('alice', 'data1', 'write'))
        self.assertFalse(e.enforce('bob', 'data1', 'read'))
        self.assertTrue(e.enforce('bob', 'data2', 'write'))
        self.assertTrue(e.enforce('alice', 'data2', 'read'))
        self.assertTrue(e.enforce('alice', 'data2', 'write'))

    def test_add_policy(self):
        '''
        test add_policy
        '''
        adapter = Adapter('mongodb://localhost:27017', 'casbin_test')
        e = casbin.Enforcer(get_fixture('rbac_model.conf'), adapter, True)

        try:
            self.assertFalse(e.enforce('alice', 'data1', 'write'))
            self.assertFalse(e.enforce('bob', 'data1', 'read'))
            self.assertFalse(e.enforce('bob', 'data2', 'write'))
            self.assertFalse(e.enforce('alice', 'data2', 'read'))
            self.assertFalse(e.enforce('alice', 'data2', 'write'))
        except simpleeval.NameNotDefined:
            # This is caused by an upstream bug when there is no policy loaded
            # Should be resolved in pycasbin >= 0.3
            pass

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
        model = casbin.Enforcer(get_fixture('rbac_model.conf'), get_fixture('rbac_policy.csv')).model
        adapter = Adapter('mongodb://localhost:27017', 'casbin_test')
        adapter.save_policy(model)
        e = casbin.Enforcer(get_fixture('rbac_model.conf'), adapter)

        self.assertFalse(e.enforce('alice', 'data1', 'read'))
        self.assertFalse(e.enforce('bob', 'data1', 'read'))
        self.assertTrue(e.enforce('bob', 'data2', 'write'))
        self.assertTrue(e.enforce('alice', 'data2', 'read'))
        self.assertTrue(e.enforce('alice', 'data2', 'write'))

    def test_str(self):
        '''
        test __str__ function
        '''
        rule = CasbinRule(ptype='p', v0='alice', v1='data1', v2='read')
        self.assertEqual(str(rule), 'p, alice, data1, read')

    def test_repr(self):
        '''
        test __repr__ function
        '''
        adapter = Adapter('mongodb://localhost:27017', 'casbin_test')
        rule = CasbinRule(ptype='p', v0='alice', v1='data1', v2='read')
        self.assertEqual(repr(rule), '<CasbinRule :"p, alice, data1, read">')
        adapter.save_policy(rule)
        self.assertRegex(repr(rule), r'<CasbinRule :"p, alice, data1, read">')