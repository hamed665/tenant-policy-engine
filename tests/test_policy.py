import tempfile
import unittest
from pathlib import Path
from policy import PolicyEngine


class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.e = PolicyEngine(str(Path(self.tmp.name) / 'policy.db'))
        for person, role in [('alice','owner'), ('bob','admin'), ('carol','analyst'), ('dave','viewer')]:
            self.e.provision_member('a', person, role)
        self.e.provision_member('b', 'alice', 'owner')
        self.e.provision_resource('doc-a', 'a', 'carol')
        self.e.provision_resource('doc-b', 'b', 'alice')
        self.e.provision_resource('secret', 'a', 'bob', classified=True)

    def tearDown(self):
        self.e.close()
        self.tmp.cleanup()

    def decision(self, subject='alice', action='read', resource='doc-a', tenant='a'):
        return self.e.decide(tenant=tenant, subject=subject, action=action, resource=resource)['allowed']

    def test_owner_all_actions(self):
        for action in ('read','update','delete','export'):
            self.assertTrue(self.decision(action=action))

    def test_cross_tenant_owner_denied(self):
        self.assertFalse(self.decision(resource='doc-b'))

    def test_unknown_subject_denied(self):
        self.assertFalse(self.decision(subject='unknown'))

    def test_unknown_action_denied(self):
        self.assertFalse(self.decision(action='grant_admin'))

    def test_viewer_read_only(self):
        self.assertTrue(self.decision(subject='dave'))
        for action in ('update','delete','export'):
            self.assertFalse(self.decision(subject='dave', action=action))

    def test_admin_export_denied(self):
        self.assertTrue(self.decision(subject='bob', action='update'))
        self.assertFalse(self.decision(subject='bob', action='export'))

    def test_analyst_own_resource_update(self):
        self.assertTrue(self.decision(subject='carol', action='update'))
        self.e.provision_resource('other', 'a', 'bob')
        self.assertFalse(self.decision(subject='carol', action='update', resource='other'))

    def test_classified_owner_only(self):
        self.assertTrue(self.decision(resource='secret'))
        self.assertFalse(self.decision(subject='bob', resource='secret'))

    def test_revocation_takes_effect(self):
        self.assertTrue(self.decision(subject='dave'))
        self.e.revoke('a', 'dave')
        self.assertFalse(self.decision(subject='dave'))

    def test_create_requires_role_and_no_existing_resource(self):
        self.assertTrue(self.decision(action='create', resource=None))
        self.assertFalse(self.decision(subject='dave', action='create', resource=None))
        self.assertFalse(self.decision(action='create'))

    def test_missing_and_foreign_same_denial(self):
        def why(resource):
            return self.e.decide(tenant='a', subject='alice', action='read', resource=resource)['reason']
        self.assertEqual(why('missing'), why('doc-b'))

    def test_denials_audited_and_tenant_filtered(self):
        self.decision(resource='doc-b')
        self.decision(tenant='b', resource='doc-b')
        rows = self.e.audit('a')
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['allowed'], 0)

    def test_invalid_role(self):
        with self.assertRaises(ValueError):
            self.e.provision_member('a', 'evil', 'superuser')
