"""Per-EAB domain restriction tests."""
import json
import pytest


def _cred(allowed):
    from models.acme_models import AcmeEabCredential
    cred = AcmeEabCredential(kid='test-kid', hmac_key_b64='')
    cred.allowed_domains = (
        json.dumps(allowed) if allowed is not None else None
    )
    return cred


@pytest.mark.parametrize('allowed,identifier,expected', [
    (['*'], {'type': 'dns', 'value': 'anything.example.org'}, True),
    (None, {'type': 'dns', 'value': 'anything.example.org'}, True),
    ([], {'type': 'dns', 'value': 'a.example.org'}, False),
    (['host.mydomain.com'], {'type': 'dns', 'value': 'host.mydomain.com'}, True),
    (['host.mydomain.com'], {'type': 'dns', 'value': 'HOST.mydomain.com.'}, True),
    (['host.mydomain.com'], {'type': 'dns', 'value': 'other.mydomain.com'}, False),
    (['*.mydomain.com'], {'type': 'dns', 'value': 'a.mydomain.com'}, True),
    (['*.mydomain.com'], {'type': 'dns', 'value': 'a.b.mydomain.com'}, True),
    (['*.mydomain.com'], {'type': 'dns', 'value': 'mydomain.com'}, False),
    (['*.mydomain.com'], {'type': 'dns', 'value': 'evilmydomain.com'}, False),
    (['*.mydomain.com'], {'type': 'dns', 'value': '*.mydomain.com'}, True),
    (['*.mydomain.com'], {'type': 'dns', 'value': '*.b.mydomain.com'}, True),
    (['host.mydomain.com'], {'type': 'dns', 'value': '*.mydomain.com'}, False),
    (['*'], {'type': 'ip', 'value': '10.0.0.1'}, True),
    (['10.0.0.1'], {'type': 'ip', 'value': '10.0.0.1'}, True),
    (['*.mydomain.com'], {'type': 'ip', 'value': '10.0.0.1'}, False),
])
def test_allows_identifier(app, allowed, identifier, expected):
    with app.app_context():
        assert _cred(allowed).allows_identifier(identifier) is expected


def test_create_and_patch_allowed_domains(auth_client):
    r = auth_client.post(
        '/api/v2/acme/eab-credentials',
        data=json.dumps({'label': 'restricted',
                         'allowed_domains': ['*.Mydomain.COM.', 'host.mydomain.com']}),
        content_type='application/json',
    )
    assert r.status_code == 201
    cred = json.loads(r.data)['data']
    assert cred['allowed_domains'] == ['*.mydomain.com', 'host.mydomain.com']

    r = auth_client.patch(
        f"/api/v2/acme/eab-credentials/{cred['id']}",
        data=json.dumps({'allowed_domains': []}),
        content_type='application/json',
    )
    assert r.status_code == 200
    assert json.loads(r.data)['data']['allowed_domains'] == []

    r = auth_client.patch(
        f"/api/v2/acme/eab-credentials/{cred['id']}",
        data=json.dumps({'allowed_domains': ['not a domain!']}),
        content_type='application/json',
    )
    assert r.status_code == 400