"""POST /api/v2/truststore/bulk/delete (#388): remove a selection at once."""
import json
import secrets

import pytest

from models import AuditLog, db
from models.truststore import TrustedCertificate

URL = '/api/v2/truststore/bulk/delete'


def _post(client, body):
    return client.post(URL, data=json.dumps(body), content_type='application/json')


@pytest.fixture
def rows(app):
    ids = []
    with app.app_context():
        for n in range(3):
            row = TrustedCertificate(
                name=f'bulk-trust-{n}', certificate_pem='-----BEGIN CERTIFICATE-----',
                fingerprint_sha256=secrets.token_hex(32), purpose='system',
            )
            db.session.add(row)
            db.session.commit()
            ids.append(row.id)
    yield ids
    with app.app_context():
        TrustedCertificate.query.filter(TrustedCertificate.id.in_(ids)).delete(synchronize_session=False)
        db.session.commit()


def _remaining(app, ids):
    with app.app_context():
        return sorted(r.id for r in TrustedCertificate.query.filter(TrustedCertificate.id.in_(ids)))


def test_removes_the_selection_and_reports_the_rest(app, auth_client, rows):
    r = _post(auth_client, {'ids': [rows[0], rows[1], 999999999, 'x']})
    assert r.status_code == 200, r.get_json()
    data = r.get_json()['data']
    assert sorted(data['success']) == sorted(rows[:2])
    assert [f['id'] for f in data['failed']] == [999999999, 'x']
    assert _remaining(app, rows) == [rows[2]]
    with app.app_context():
        log = AuditLog.query.filter_by(action='truststore_bulk_remove').order_by(AuditLog.id.desc()).first()
        assert log is not None and 'bulk-trust-0' in log.details and 'bulk-trust-1' in log.details


def test_requires_the_delete_permission(app, viewer_client, rows):
    assert _post(viewer_client, {'ids': rows}).status_code == 403
    assert _remaining(app, rows) == sorted(rows)


def test_requires_authentication(client):
    assert _post(client, {'ids': [1]}).status_code == 401


@pytest.mark.parametrize('body', [{}, {'ids': 'abc'}, {'ids': list(range(1, 102))}])
def test_refuses_a_malformed_selection(auth_client, body):
    assert _post(auth_client, body).status_code == 400
