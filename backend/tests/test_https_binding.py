"""
HTTPS certificate binding (#303 M1): the certificate applied to HTTPS is
remembered by refid; its renewal re-materializes the files and restarts the
service; regenerating a self-signed certificate clears the binding.
"""
from unittest.mock import MagicMock

import pytest

import services.https_binding as https_binding
from services.https_binding import (
    get_bound_refid, on_certificate_renewed, set_bound_refid,
)


@pytest.fixture
def clean_binding(app):
    with app.app_context():
        set_bound_refid('')
    yield
    with app.app_context():
        set_bound_refid('')


class TestBindingStore:
    def test_roundtrip(self, app, clean_binding):
        with app.app_context():
            assert get_bound_refid() == ''
            set_bound_refid('cert-ref-1')
            assert get_bound_refid() == 'cert-ref-1'
            set_bound_refid('')
            assert get_bound_refid() == ''


class TestRenewalSubscriber:
    def _payload(self, refid):
        return {'certificate': {'refid': refid, 'id': 1}}

    def test_other_certificate_is_ignored(self, app, clean_binding, monkeypatch):
        materialize = MagicMock()
        monkeypatch.setattr(https_binding, 'materialize_https_cert', materialize)
        with app.app_context():
            set_bound_refid('bound-ref')
            on_certificate_renewed('certificate.renewed',
                                   self._payload('other-ref'), None, {})
        assert materialize.call_count == 0

    def test_no_binding_is_a_noop(self, app, clean_binding, monkeypatch):
        materialize = MagicMock()
        monkeypatch.setattr(https_binding, 'materialize_https_cert', materialize)
        with app.app_context():
            on_certificate_renewed('certificate.renewed',
                                   self._payload('any'), None, {})
        assert materialize.call_count == 0

    def test_bound_certificate_rematerializes_and_restarts(
        self, app, clean_binding, monkeypatch, create_cert,
    ):
        restart = MagicMock(return_value=(True, 'ok'))
        materialize = MagicMock()
        monkeypatch.setattr(https_binding, 'materialize_https_cert', materialize)
        import utils.service_manager as sm
        monkeypatch.setattr(sm, 'restart_service', restart)
        monkeypatch.delenv('UCM_DOCKER', raising=False)

        cert = create_cert()
        refid = cert.get('refid')
        assert refid, cert
        with app.app_context():
            set_bound_refid(refid)
            on_certificate_renewed(
                'certificate.renewed',
                {'certificate': {'refid': refid, 'id': cert.get('id')}}, None, {},
            )
        assert materialize.call_count == 1
        assert restart.call_count == 1

    def test_subscriber_never_raises(self, app, clean_binding, monkeypatch):
        def boom(_cert):
            raise RuntimeError('disk full')
        monkeypatch.setattr(https_binding, 'materialize_https_cert', boom)
        with app.app_context():
            set_bound_refid('x')
            # missing cert row → warning path, no exception
            on_certificate_renewed('certificate.renewed',
                                   self._payload('x'), None, {})
