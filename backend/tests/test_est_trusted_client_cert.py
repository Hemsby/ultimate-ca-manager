"""
Regression tests for est_protocol._trusted_client_cert().

PR #248 made the reverse-proxy client-cert path fail closed (a missing
SSL_CLIENT_VERIFY no longer counts as success) but shipped no test, and the
new warning fired on EVERY ordinary Basic-auth request arriving through a
trusted proxy that forwards no SSL_CLIENT_* variables at all — the exact
setup of the sample nginx config in docs/installation/docker.md.

These tests call the function directly under a bare Flask request context
(no UCM create_app, no database), so they also run on hosts where the shared
`app` fixture cannot start. The function only passes the certificate value
through, so an opaque sentinel stands in for a real PEM.
"""
import logging

import pytest
from flask import Flask

from api import est_protocol

CLIENT_CERT = "sentinel-client-cert-value"
LOGGER_NAME = est_protocol.logger.name


@pytest.fixture()
def bare_app(monkeypatch):
    # Default trusted-proxy set is loopback; make sure the environment does
    # not widen or narrow it.
    monkeypatch.delenv('UCM_TRUSTED_PROXIES', raising=False)
    return Flask(__name__)


def _warnings(caplog):
    return [
        r for r in caplog.records
        if r.name == LOGGER_NAME and r.levelno >= logging.WARNING
    ]


def test_missing_verify_with_presented_cert_is_refused_and_warned(bare_app, caplog):
    """Fail-closed regression (the #248 behavior change itself, untested there):
    a trusted proxy forwarding a certificate WITHOUT a verify result must have
    the certificate refused — and that genuine anomaly must be logged."""
    with bare_app.test_request_context(
        '/.well-known/est/simpleenroll',
        environ_base={'REMOTE_ADDR': '127.0.0.1'},
        headers={'X-SSL-Client-Cert': CLIENT_CERT},
    ):
        with caplog.at_level(logging.DEBUG, logger=LOGGER_NAME):
            result = est_protocol._trusted_client_cert()

    assert result is None
    warnings = _warnings(caplog)
    assert len(warnings) == 1
    assert 'refusing client cert' in warnings[0].getMessage()


def test_basic_auth_request_without_cert_logs_no_warning(bare_app, caplog):
    """An ordinary Basic-auth request through a same-host proxy carries no
    SSL_CLIENT_* variables at all. It must still be refused a client cert
    (fail closed) but must NOT warn 'refusing client cert' — no certificate
    was ever presented, and this is the normal success path."""
    with bare_app.test_request_context(
        '/.well-known/est/simpleenroll',
        environ_base={'REMOTE_ADDR': '127.0.0.1'},
    ):
        with caplog.at_level(logging.DEBUG, logger=LOGGER_NAME):
            result = est_protocol._trusted_client_cert()

    assert result is None
    assert _warnings(caplog) == []


def test_verified_cert_is_returned_without_warning(bare_app, caplog):
    with bare_app.test_request_context(
        '/.well-known/est/simpleenroll',
        environ_base={'REMOTE_ADDR': '127.0.0.1'},
        headers={
            'X-SSL-Client-Verify': 'SUCCESS',
            'X-SSL-Client-Cert': CLIENT_CERT,
        },
    ):
        with caplog.at_level(logging.DEBUG, logger=LOGGER_NAME):
            result = est_protocol._trusted_client_cert()

    assert result == CLIENT_CERT
    assert _warnings(caplog) == []


def test_failed_verify_with_cert_still_warns(bare_app, caplog):
    """nginx with `ssl_verify_client optional` forwards e.g. 'FAILED' — a
    presented-but-unverified certificate keeps its warning (pre-existing
    behavior, must not be silenced by the noise fix)."""
    with bare_app.test_request_context(
        '/.well-known/est/simpleenroll',
        environ_base={'REMOTE_ADDR': '127.0.0.1'},
        headers={
            'X-SSL-Client-Verify': 'FAILED',
            'X-SSL-Client-Cert': CLIENT_CERT,
        },
    ):
        with caplog.at_level(logging.DEBUG, logger=LOGGER_NAME):
            result = est_protocol._trusted_client_cert()

    assert result is None
    warnings = _warnings(caplog)
    assert len(warnings) == 1
    assert 'refusing client cert' in warnings[0].getMessage()


def test_untrusted_peer_cert_headers_are_ignored_and_warned(bare_app, caplog):
    """A peer outside the trusted-proxy set sending cert headers is a spoof
    attempt: refuse and log, regardless of what the headers claim."""
    with bare_app.test_request_context(
        '/.well-known/est/simpleenroll',
        environ_base={'REMOTE_ADDR': '203.0.113.7'},
        headers={
            'X-SSL-Client-Verify': 'SUCCESS',
            'X-SSL-Client-Cert': CLIENT_CERT,
        },
    ):
        with caplog.at_level(logging.DEBUG, logger=LOGGER_NAME):
            result = est_protocol._trusted_client_cert()

    assert result is None
    warnings = _warnings(caplog)
    assert len(warnings) == 1
    assert 'untrusted peer' in warnings[0].getMessage()
