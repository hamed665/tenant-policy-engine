import json
from policy import PolicyEngine


def run():
    e = PolicyEngine(':memory:')
    try:
        e.provision_member('demo-a','alice','owner')
        e.provision_member('demo-a','bob','viewer')
        e.provision_resource('invoice-a','demo-a','alice')
        e.provision_resource('invoice-b','demo-b','mallory')
        results = []
        for subject, action, resource in [('alice','read','invoice-a'), ('bob','delete','invoice-a'),
                                          ('alice','read','invoice-b')]:
            decision = e.decide(tenant='demo-a', subject=subject, action=action, resource=resource)
            results.append(dict(subject=subject, action=action, resource=resource, **decision))
        e.revoke('demo-a','bob')
        revoked = e.decide(tenant='demo-a',subject='bob',action='read',resource='invoice-a')
        return {'synthetic':True,'decisions':results,'after_revocation':revoked,'audit':e.audit('demo-a')}
    finally:
        e.close()


if __name__ == '__main__':
    print(json.dumps(run(),indent=2))
