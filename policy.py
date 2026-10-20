"""Server-owned tenant membership, resource policy and atomic decision audit."""
import json
import sqlite3


class PolicyEngine:
    ROLES = {'owner', 'admin', 'analyst', 'viewer'}
    ACTIONS = {'read', 'create', 'update', 'delete', 'export'}

    def __init__(self, path):
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        self.db.executescript('''
          CREATE TABLE IF NOT EXISTS memberships (
            tenant TEXT, subject TEXT, role TEXT NOT NULL, PRIMARY KEY(tenant,subject));
          CREATE TABLE IF NOT EXISTS resources (
            id TEXT PRIMARY KEY, tenant TEXT NOT NULL, owner TEXT NOT NULL, classified INTEGER NOT NULL);
          CREATE TABLE IF NOT EXISTS decisions (
            seq INTEGER PRIMARY KEY, tenant TEXT, subject TEXT, action TEXT,
            resource TEXT, allowed INTEGER NOT NULL, reason TEXT NOT NULL);
        ''')

    def close(self):
        self.db.close()

    def provision_member(self, tenant, subject, role):
        """Administrative provisioning API. Never expose to untrusted callers."""
        if role not in self.ROLES or not tenant or not subject:
            raise ValueError('Invalid membership')
        with self.db:
            self.db.execute('INSERT OR REPLACE INTO memberships VALUES (?,?,?)', (tenant, subject, role))

    def revoke(self, tenant, subject):
        with self.db:
            self.db.execute('DELETE FROM memberships WHERE tenant=? AND subject=?', (tenant, subject))

    def provision_resource(self, resource, tenant, owner, *, classified=False):
        if not all(isinstance(x, str) and x for x in (resource, tenant, owner)):
            raise ValueError('Invalid resource')
        with self.db:
            self.db.execute('INSERT INTO resources VALUES (?,?,?,?)', (resource, tenant, owner, bool(classified)))

    def decide(self, *, tenant, subject, action, resource=None):
        """subject must come from a verified identity, never from a request body."""
        with self.db:
            # Acquire a write transaction before reading policy, so revocation
            # cannot race a decision's audit record on another connection.
            self.db.execute('BEGIN IMMEDIATE')
            member = self.db.execute('SELECT role FROM memberships WHERE tenant=? AND subject=?',
                                     (tenant, subject)).fetchone()
            obj = self.db.execute('SELECT * FROM resources WHERE id=?', (resource,)).fetchone() if resource else None
            allowed, reason = False, 'membership required'
            if action not in self.ACTIONS:
                reason = 'unknown action'
            elif member:
                role = member['role']
                reason = 'resource unavailable'
                if action == 'create' and resource is None:
                    allowed = role in {'owner', 'admin'}
                    reason = 'create policy'
                elif action != 'create' and obj and obj['tenant'] == tenant:
                    if obj['classified'] and role != 'owner':
                        reason = 'classified resource requires tenant owner'
                    else:
                        allowed = (role == 'owner' or
                                   role == 'admin' and action != 'export' or
                                   role == 'analyst' and (action in {'read', 'export'} or
                                                         action == 'update' and obj['owner'] == subject) or
                                   role == 'viewer' and action == 'read')
                        reason = 'role and resource policy'
            self.db.execute('INSERT INTO decisions (tenant,subject,action,resource,allowed,reason) VALUES (?,?,?,?,?,?)',
                            (tenant, subject, action, resource, allowed, reason))
        return {'allowed': bool(allowed), 'reason': reason}

    def audit(self, tenant):
        """Trusted operator API; callers must enforce operator authentication."""
        return [dict(r) for r in self.db.execute('SELECT * FROM decisions WHERE tenant=? ORDER BY seq', (tenant,))]
