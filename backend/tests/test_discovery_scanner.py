"""Discovery scanner regression tests (#293).

A scheduled scan of a /16 across 9 ports (~590k probes) used to queue every
probe up front, retain every result dict in memory, and — because the profile's
next_scan_at only advanced on completion — be re-triggered 60s after every
process restart, producing an OOM crash loop. These tests pin the fixes: a
total-probe cap, windowed execution with selective result retention, scheduler
re-trigger protection, and stale-run recovery at boot.
"""
import json
from datetime import datetime, timezone, timedelta

import pytest

from models import db, ScanProfile, ScanRun, DiscoveredCertificate
from services.discovery import DiscoveryService
from services.discovery.helpers import _MAX_SCAN_JOBS
from services.discovery_scheduler_task import DiscoverySchedulerTask


@pytest.fixture
def service():
    return DiscoveryService()


@pytest.fixture
def no_scan_thread(monkeypatch):
    """Capture the scan thread instead of running it."""
    captured = {}

    class FakeThread:
        def __init__(self, target=None, args=(), daemon=None):
            captured['target'] = target
            captured['args'] = args

        def start(self):
            pass

    monkeypatch.setattr('services.discovery.scanner.threading.Thread', FakeThread)
    return captured


@pytest.fixture
def quiet_emitters(monkeypatch):
    for name in ('on_discovery_scan_started', 'on_discovery_scan_progress',
                 'on_discovery_scan_complete', 'on_discovery_new_cert',
                 'on_discovery_cert_changed'):
        monkeypatch.setattr(f'websocket.emitters.{name}', lambda *a, **k: None)


def test_scan_rejects_host_port_explosion(app, service, no_scan_thread):
    """A /16 across two ports exceeds the total-probe cap and must be refused."""
    with app.app_context():
        with pytest.raises(ValueError, match='max'):
            service.start_scan(['10.0.0.0/16'], ports=[443, 8443])


def test_scan_cap_releases_semaphore(app, service, no_scan_thread):
    """A rejected scan must not leak its concurrency slot."""
    with app.app_context():
        for _ in range(5):  # more attempts than _MAX_CONCURRENT_SCANS
            with pytest.raises(ValueError, match='max'):
                service.start_scan(['10.0.0.0/16'], ports=[443, 8443])
        run_id = service.start_scan(['192.0.2.0/29'], ports=[443])
        run = db.session.get(ScanRun, run_id)
        assert run is not None
        assert run.total_targets == 6


def test_do_scan_windowed_execution(app, service, monkeypatch, quiet_emitters):
    """Windowed scan completes, counts errors, saves certs and TLS errors only."""
    jobs = [(f'192.0.2.{i}', 443) for i in range(1, 40)]
    cert_target, tls_err_target, timeout_target = '192.0.2.1', '192.0.2.2', '192.0.2.3'

    def fake_probe(self, host, port, timeout=None, resolve_dns=False, sni_hostname=None):
        r = {'target': host, 'port': port}
        if sni_hostname:
            r['sni_hostname'] = sni_hostname
            r.update({'error': 'Connection refused', 'error_type': 'refused'})
        elif host == cert_target:
            r.update({
                'subject': 'CN=scan-target.test', 'issuer': 'CN=Test CA',
                'serial_number': '1A', 'not_before': '2026-01-01T00:00:00+00:00',
                'not_after': '2027-01-01T00:00:00+00:00',
                'fingerprint_sha256': 'AB' * 32,
                'pem_certificate': '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----',
                'san_dns_names': ['scan-target.test'], 'san_ip_addresses': [],
                'san_emails': [], 'san_uris': [],
            })
        elif host == tls_err_target:
            r.update({'error': 'handshake failure', 'error_type': 'tls'})
        elif host == timeout_target:
            r.update({'error': 'Connection timed out', 'error_type': 'timeout'})
        else:
            r.update({'error': 'Connection refused', 'error_type': 'refused'})
        return r

    monkeypatch.setattr(DiscoveryService, 'probe_tls', fake_probe)
    monkeypatch.setattr(DiscoveryService, '_send_notifications', lambda self, *a, **k: None)

    with app.app_context():
        run = ScanRun(total_targets=len(jobs), triggered_by='manual')
        db.session.add(run)
        db.session.commit()
        run_id = run.id

        service._do_scan(run_id, jobs, None, timeout=1, max_workers=4)

        run = db.session.get(ScanRun, run_id)
        assert run.status == 'completed'
        # Every probe was executed despite the bounded submission window,
        # plus one SNI re-probe of the discovered cert's SAN hostname
        assert run.targets_scanned == len(jobs) + 1
        assert run.certs_found == 1
        assert run.errors == 2  # tls error + timeout; refused is not an error

        saved = {d.target: d for d in DiscoveredCertificate.query.filter(
            DiscoveredCertificate.target.in_([t for t, _ in jobs])).all()}
        assert cert_target in saved
        assert saved[cert_target].fingerprint_sha256 == 'AB' * 32
        assert tls_err_target in saved
        assert saved[tls_err_target].status == 'error'
        # Connection-level failures are dropped, not saved
        assert timeout_target not in saved
        assert '192.0.2.10' not in saved


def _make_profile(name, next_scan_at):
    profile = ScanProfile(
        name=name,
        targets=json.dumps(['192.0.2.10']),
        ports=json.dumps([443]),
        schedule_enabled=True,
        schedule_interval_minutes=60,
        next_scan_at=next_scan_at,
    )
    db.session.add(profile)
    db.session.commit()
    return profile


def test_scheduler_advances_next_scan_before_start(app, monkeypatch):
    """next_scan_at moves forward when the scan STARTS, not when it completes —
    a crashed or long-running scan must not re-trigger on every check (#293)."""
    calls = []
    monkeypatch.setattr(DiscoveryService, 'start_scan',
                        lambda self, **kw: calls.append(kw) or 1)

    with app.app_context():
        now = datetime.now(timezone.utc)
        profile = _make_profile('scan-advance-test', now - timedelta(minutes=5))

        DiscoverySchedulerTask.execute()

        assert len(calls) == 1
        db.session.refresh(profile)
        assert profile.next_scan_at.replace(tzinfo=timezone.utc) > now


def test_scheduler_skips_profile_with_running_scan(app, monkeypatch):
    calls = []
    monkeypatch.setattr(DiscoveryService, 'start_scan',
                        lambda self, **kw: calls.append(kw) or 1)

    with app.app_context():
        now = datetime.now(timezone.utc)
        profile = _make_profile('scan-skip-running-test', now - timedelta(minutes=5))
        db.session.add(ScanRun(scan_profile_id=profile.id, status='running'))
        db.session.commit()

        DiscoverySchedulerTask.execute()

        assert calls == []
        db.session.refresh(profile)
        # Deferred, but pushed one interval forward — no 60s retry hammering
        assert profile.next_scan_at.replace(tzinfo=timezone.utc) > now


def test_recover_stale_runs(app):
    with app.app_context():
        run = ScanRun(status='running', triggered_by='scheduled')
        db.session.add(run)
        db.session.commit()
        run_id = run.id

        recovered = DiscoverySchedulerTask.recover_stale_runs()

        assert recovered >= 1
        run = db.session.get(ScanRun, run_id)
        assert run.status == 'failed'
        assert run.completed_at is not None
        assert ScanRun.query.filter_by(status='running').count() == 0


def test_probe_refused_does_no_ptr_lookup(app, service, monkeypatch):
    """The PTR-hostname SNI fallback is lazy: a dead host must not trigger a
    reverse DNS lookup — one PTR query per probed IP hammers DNS on subnet
    scans (#293)."""
    import socket as socket_mod

    def refuse(*a, **k):
        raise ConnectionRefusedError()

    def no_ptr(*a, **k):
        raise AssertionError('gethostbyaddr must not be called for a dead host')

    monkeypatch.setattr(socket_mod, 'create_connection', refuse)
    monkeypatch.setattr(socket_mod, 'gethostbyaddr', no_ptr)

    result = service.probe_tls('192.0.2.99', 443, timeout=1)
    assert result['error_type'] == 'refused'
