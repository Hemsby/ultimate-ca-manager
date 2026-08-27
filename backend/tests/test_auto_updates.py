"""
Automatic updates (#301): SHA256 checksum verification, the scheduled
check/notify/install task, and the update-settings API.
"""
import hashlib
import json
import os

import pytest

import services.updates as updates


def _clear_update_config(app):
    from models import db, SystemConfig
    with app.app_context():
        for key in (
            updates.UPDATE_CHANNEL_KEY, updates.AUTO_UPDATE_ENABLED_KEY,
            updates.AUTO_UPDATE_HOUR_KEY, updates._LAST_CHECK_TS_KEY,
            updates._NOTIFIED_VERSION_KEY, updates._ATTEMPTED_VERSION_KEY,
        ):
            SystemConfig.query.filter_by(key=key).delete()
        db.session.commit()


@pytest.fixture
def clean_update_config(app):
    _clear_update_config(app)
    yield
    _clear_update_config(app)


class _FakeResponse:
    def __init__(self, content=b'', text=''):
        self.content = content
        self.text = text

    def raise_for_status(self):
        pass

    def iter_content(self, chunk_size=8192):
        for i in range(0, len(self.content), chunk_size):
            yield self.content[i:i + chunk_size]


class TestFetchExpectedSha256:
    def test_parses_sha256sum_output(self, monkeypatch):
        digest = 'a' * 64
        monkeypatch.setattr(updates.requests, 'get', lambda *a, **k: _FakeResponse(
            text=f'{digest}  ucm_2.215_all.deb\n'))
        assert updates.fetch_expected_sha256('http://x/f.sha256', 'ucm_2.215_all.deb') == digest

    def test_matches_basename_and_binary_marker(self, monkeypatch):
        digest = 'b' * 64
        monkeypatch.setattr(updates.requests, 'get', lambda *a, **k: _FakeResponse(
            text=f'{"c" * 64}  other.rpm\n{digest} *./out/ucm-2.215.noarch.rpm\n'))
        assert updates.fetch_expected_sha256(
            'http://x/c.sha256', 'ucm-2.215.noarch.rpm') == digest

    def test_no_match_returns_none(self, monkeypatch):
        monkeypatch.setattr(updates.requests, 'get', lambda *a, **k: _FakeResponse(
            text=f'{"d" * 64}  something-else.deb\nnot a checksum line\n'))
        assert updates.fetch_expected_sha256('http://x/f.sha256', 'ucm.deb') is None


class TestDownloadChecksum:
    def test_mismatch_removes_file_and_raises(self, monkeypatch, tmp_path):
        monkeypatch.setattr(updates, 'DATA_DIR', str(tmp_path))
        monkeypatch.setattr(updates.requests, 'get', lambda *a, **k: _FakeResponse(
            content=b'package-bytes'))
        with pytest.raises(Exception, match='Checksum mismatch'):
            updates.download_update('http://x/p.deb', 'p.deb', expected_sha256='0' * 64)
        assert not (tmp_path / 'updates' / 'p.deb').exists()

    def test_match_keeps_file(self, monkeypatch, tmp_path):
        content = b'package-bytes'
        monkeypatch.setattr(updates, 'DATA_DIR', str(tmp_path))
        monkeypatch.setattr(updates.requests, 'get', lambda *a, **k: _FakeResponse(
            content=content))
        path = updates.download_update(
            'http://x/p.deb', 'p.deb',
            expected_sha256=hashlib.sha256(content).hexdigest().upper())
        assert os.path.exists(path)


class TestCheckForUpdatesChecksumUrl:
    def test_checksum_url_exposed_for_chosen_asset(self, monkeypatch):
        import time as _time
        monkeypatch.setitem(updates._releases_cache, 'data', [{
            'tag_name': 'v99.0', 'draft': False, 'prerelease': False,
            'body': '', 'assets': [
                {'name': 'ucm_99.0_all.deb',
                 'browser_download_url': 'http://x/ucm_99.0_all.deb'},
                {'name': 'ucm_99.0_all.deb.sha256',
                 'browser_download_url': 'http://x/ucm_99.0_all.deb.sha256'},
            ],
        }])
        monkeypatch.setitem(updates._releases_cache, 'ts', _time.time())
        monkeypatch.setattr(updates.os.path, 'exists',
                            lambda p: p == '/usr/bin/dpkg')
        result = updates.check_for_updates()
        assert result['update_available'] is True
        assert result['package_name'] == 'ucm_99.0_all.deb'
        assert result['checksum_url'] == 'http://x/ucm_99.0_all.deb.sha256'


def _release(tag, prerelease=False):
    return {
        'tag_name': tag, 'draft': False, 'prerelease': prerelease, 'body': '',
        'assets': [
            {'name': f'ucm_{tag.lstrip("v")}_all.deb',
             'browser_download_url': f'http://x/ucm_{tag.lstrip("v")}_all.deb'},
        ],
    }


class TestChannelFilter:
    """Strict channels (review F-04): 'rc' must never pick alpha/beta/dev."""

    def _seed(self, monkeypatch, releases):
        import time as _time
        monkeypatch.setitem(updates._releases_cache, 'data', releases)
        monkeypatch.setitem(updates._releases_cache, 'ts', _time.time())
        monkeypatch.setattr(updates.os.path, 'exists',
                            lambda p: p == '/usr/bin/dpkg')

    def test_stable_channel_ignores_all_prereleases(self, monkeypatch):
        self._seed(monkeypatch, [
            _release('v99.3-beta1', prerelease=True),
            _release('v99.2-rc1', prerelease=True),
            _release('v99.1-alpha1', prerelease=True),
            _release('v99.0'),
        ])
        result = updates.check_for_updates(channel='stable')
        assert result['latest_version'] == '99.0'

    def test_rc_channel_takes_rc_but_never_beta_alpha_dev(self, monkeypatch):
        self._seed(monkeypatch, [
            _release('v99.4-dev1', prerelease=True),
            _release('v99.3-beta1', prerelease=True),
            _release('v99.2-alpha2', prerelease=True),
            _release('v99.1-rc1', prerelease=True),
            _release('v99.0'),
        ])
        result = updates.check_for_updates(channel='rc')
        # a newer beta/alpha/dev must NOT shadow the rc candidate
        assert result['latest_version'] == '99.1-rc1'

    def test_rc_channel_still_takes_newer_stable(self, monkeypatch):
        self._seed(monkeypatch, [
            _release('v99.2'),
            _release('v99.1-rc9', prerelease=True),
        ])
        result = updates.check_for_updates(channel='rc')
        assert result['latest_version'] == '99.2'


class TestUpdateResultConsumption:
    """R-01: system.update_installed / system.update_failed come from the
    watcher's durable result, consumed exactly once."""

    def _write_result(self, tmp_path, **over):
        data = {
            'op_id': 'abc123', 'from_version': '2.0', 'to_version': '99.0',
            'initiated_by': 'scheduler', 'status': 'installed',
            'installed_version': '99.0', 'step': None, 'error': None,
        }
        data.update(over)
        (tmp_path / '.update_result.json').write_text(json.dumps(data))

    def test_installed_result_emits_installed_once(
            self, app, monkeypatch, tmp_path):
        import services.webhook_service as wh
        events = []
        monkeypatch.setattr(updates, 'DATA_DIR', str(tmp_path))
        monkeypatch.setattr(wh, 'emit_update_installed',
                            lambda update, actor=None: events.append(update))
        self._write_result(tmp_path)
        with app.app_context():
            result = updates.consume_update_result()
            assert result['status'] == 'installed'
            assert updates.consume_update_result() is None  # consumed once
        assert len(events) == 1
        assert events[0]['latest_version'] == '99.0'
        assert not (tmp_path / '.update_result.json').exists()

    def test_failed_result_emits_failed(self, app, monkeypatch, tmp_path):
        import services.webhook_service as wh
        events = []
        monkeypatch.setattr(updates, 'DATA_DIR', str(tmp_path))
        monkeypatch.setattr(wh, 'emit_update_failed',
                            lambda update, actor=None: events.append(update))
        monkeypatch.setattr(wh, 'emit_update_installed',
                            lambda *a, **k: events.append('WRONG'))
        self._write_result(tmp_path, status='failed', step='dpkg',
                           error='dpkg exited 1', installed_version='2.0')
        with app.app_context():
            updates.consume_update_result()
        assert len(events) == 1
        assert events[0]['error'] == 'dpkg exited 1'
        assert events[0]['step'] == 'dpkg'

    def test_installed_with_version_mismatch_downgraded_to_failed(
            self, app, monkeypatch, tmp_path):
        """Backend re-verifies the watcher's claim: 'installed' without a
        matching version must emit update_failed, never update_installed."""
        import services.webhook_service as wh
        events = []
        monkeypatch.setattr(updates, 'DATA_DIR', str(tmp_path))
        monkeypatch.setattr(wh, 'emit_update_installed',
                            lambda *a, **k: events.append(('installed',)))
        monkeypatch.setattr(wh, 'emit_update_failed',
                            lambda update, actor=None: events.append(('failed', update)))
        self._write_result(tmp_path, status='installed', installed_version='2.0')
        with app.app_context():
            updates.consume_update_result()
        assert len(events) == 1 and events[0][0] == 'failed'
        assert events[0][1]['step'] == 'verify'

    def test_installed_accepts_package_revision_suffix(
            self, app, monkeypatch, tmp_path):
        import services.webhook_service as wh
        events = []
        monkeypatch.setattr(updates, 'DATA_DIR', str(tmp_path))
        monkeypatch.setattr(wh, 'emit_update_installed',
                            lambda update, actor=None: events.append(update))
        self._write_result(tmp_path, installed_version='99.0-1')
        with app.app_context():
            updates.consume_update_result()
        assert len(events) == 1

    def test_corrupt_result_is_discarded_silently(
            self, app, monkeypatch, tmp_path):
        import services.webhook_service as wh
        events = []
        monkeypatch.setattr(updates, 'DATA_DIR', str(tmp_path))
        monkeypatch.setattr(wh, 'emit_update_installed',
                            lambda *a, **k: events.append('x'))
        monkeypatch.setattr(wh, 'emit_update_failed',
                            lambda *a, **k: events.append('x'))
        (tmp_path / '.update_result.json').write_text('{not json')
        with app.app_context():
            assert updates.consume_update_result() is None
        assert events == []
        assert not (tmp_path / '.update_result.json').exists()

    def test_no_result_file_is_noop(self, app, monkeypatch, tmp_path):
        monkeypatch.setattr(updates, 'DATA_DIR', str(tmp_path))
        with app.app_context():
            assert updates.consume_update_result() is None


class TestNotifyMarker:
    def test_marker_failure_is_visible(self, app, clean_update_config, monkeypatch):
        """R-05: a failed dedup-marker persist must not be silent."""
        import services.webhook_service as wh
        events = []
        monkeypatch.setattr(wh, 'emit_update_available',
                            lambda update: events.append(update))
        monkeypatch.setattr(updates, '_cfg_set', lambda k, v: False)
        with app.app_context():
            ok = updates._notify_update_available({
                'current_version': '2.0', 'latest_version': '99.0',
                'html_url': 'http://x', 'prerelease': False,
            })
        assert ok is False
        assert len(events) == 1  # emitted, but the failure is reported


class TestScheduledTask:
    def _base_result(self, **over):
        result = {
            'update_available': True, 'current_version': '2.0',
            'latest_version': '99.0', 'download_url': 'http://x/p.deb',
            'package_name': 'p.deb', 'checksum_url': 'http://x/p.deb.sha256',
            'html_url': 'http://x/rel', 'prerelease': False,
        }
        result.update(over)
        return result

    def test_notifies_once_per_version(self, app, clean_update_config, monkeypatch):
        events = []
        monkeypatch.setattr(updates, 'check_for_updates',
                            lambda **k: self._base_result())
        import services.webhook_service as wh
        monkeypatch.setattr(wh, 'emit_update_available',
                            lambda update: events.append(update))
        with app.app_context():
            updates.scheduled_update_check()
            updates._cfg_set(updates._LAST_CHECK_TS_KEY, '0')  # force re-check
            updates.scheduled_update_check()
        assert len(events) == 1
        assert events[0]['latest_version'] == '99.0'

    def test_no_install_when_opt_out(self, app, clean_update_config, monkeypatch):
        installed = []
        monkeypatch.setattr(updates, 'check_for_updates',
                            lambda **k: self._base_result())
        monkeypatch.setattr(updates, 'download_update',
                            lambda *a, **k: installed.append('dl') or '/tmp/p.deb')
        monkeypatch.setattr(updates, 'install_update',
                            lambda p, **k: installed.append('install'))
        with app.app_context():
            updates.scheduled_update_check()
        assert installed == []

    def _enable_auto(self, app, hour):
        with app.app_context():
            updates._cfg_set(updates.AUTO_UPDATE_ENABLED_KEY, 'true')
            updates._cfg_set(updates.AUTO_UPDATE_HOUR_KEY, str(hour))

    def test_installs_in_window_with_checksum(self, app, clean_update_config, monkeypatch):
        from datetime import datetime
        calls = []
        monkeypatch.setattr(updates, 'check_for_updates',
                            lambda **k: self._base_result())
        monkeypatch.setattr(updates, 'fetch_expected_sha256',
                            lambda url, name: 'e' * 64)
        monkeypatch.setattr(
            updates, 'download_update',
            lambda url, name, expected_sha256=None:
                calls.append(('download', expected_sha256)) or '/tmp/p.deb')
        monkeypatch.setattr(updates, 'install_update',
                            lambda p, **k: calls.append(('install', p)))
        self._enable_auto(app, datetime.now().hour)
        with app.app_context():
            updates.scheduled_update_check()
            # second tick in the same window: one attempt per version only
            updates.scheduled_update_check()
        assert calls == [('download', 'e' * 64), ('install', '/tmp/p.deb')]

    def test_auto_install_emits_initiated_not_installed(
            self, app, clean_update_config, monkeypatch, tmp_path):
        """R-01: the trigger only warrants 'initiated' — 'installed' comes
        from the watcher's durable result after the restart."""
        from datetime import datetime
        import services.webhook_service as wh
        events = []
        monkeypatch.setattr(updates, 'DATA_DIR', str(tmp_path))
        monkeypatch.setattr(updates, 'check_for_updates',
                            lambda **k: self._base_result())
        monkeypatch.setattr(updates, 'fetch_expected_sha256',
                            lambda url, name: 'e' * 64)
        monkeypatch.setattr(updates, 'download_update',
                            lambda *a, **k: '/tmp/p.deb')
        monkeypatch.setattr(wh, 'emit_update_initiated',
                            lambda *a, **k: events.append('initiated'))
        monkeypatch.setattr(wh, 'emit_update_installed',
                            lambda *a, **k: events.append('installed'))
        self._enable_auto(app, datetime.now().hour)
        with app.app_context():
            updates.scheduled_update_check()
        assert events == ['initiated']
        # trigger + manifest both written
        assert (tmp_path / '.update_pending').read_text() == '/tmp/p.deb'
        manifest = json.loads((tmp_path / '.update_manifest.json').read_text())
        assert manifest['to_version'] == '99.0'
        assert manifest['op_id']

    def test_trigger_failure_emits_no_installed_event(
            self, app, clean_update_config, monkeypatch):
        """Review F-05: a failed install trigger must not audit/emit 'installed'."""
        from datetime import datetime
        import services.webhook_service as wh
        events = []
        monkeypatch.setattr(updates, 'check_for_updates',
                            lambda **k: self._base_result())
        monkeypatch.setattr(updates, 'fetch_expected_sha256',
                            lambda url, name: 'e' * 64)
        monkeypatch.setattr(updates, 'download_update',
                            lambda *a, **k: '/tmp/p.deb')
        def _boom(path, **k):
            raise Exception('trigger write failed')
        monkeypatch.setattr(updates, 'install_update', _boom)
        monkeypatch.setattr(wh, 'emit_update_installed',
                            lambda *a, **k: events.append('installed'))
        self._enable_auto(app, datetime.now().hour)
        with app.app_context():
            updates.scheduled_update_check()
        assert events == []

    def test_no_install_when_attempt_marker_not_persisted(
            self, app, clean_update_config, monkeypatch):
        """Review F-06: without the anti-repeat marker, do not install."""
        from datetime import datetime
        calls = []
        monkeypatch.setattr(updates, 'check_for_updates',
                            lambda **k: self._base_result())
        monkeypatch.setattr(updates, 'download_update',
                            lambda *a, **k: calls.append('download'))
        monkeypatch.setattr(updates, 'install_update',
                            lambda p: calls.append('install'))
        self._enable_auto(app, datetime.now().hour)
        # settings are in place — now make every further persist fail
        monkeypatch.setattr(updates, '_cfg_set', lambda k, v: False)
        with app.app_context():
            updates.scheduled_update_check()
        assert calls == []

    def test_refuses_install_without_checksum(self, app, clean_update_config, monkeypatch):
        from datetime import datetime
        installed = []
        monkeypatch.setattr(updates, 'check_for_updates',
                            lambda **k: self._base_result(checksum_url=None))
        monkeypatch.setattr(updates, 'download_update',
                            lambda *a, **k: installed.append('dl'))
        monkeypatch.setattr(updates, 'install_update',
                            lambda p, **k: installed.append('install'))
        self._enable_auto(app, datetime.now().hour)
        with app.app_context():
            updates.scheduled_update_check()
        assert installed == []

    def test_outside_window_no_install(self, app, clean_update_config, monkeypatch):
        from datetime import datetime
        installed = []
        monkeypatch.setattr(updates, 'check_for_updates',
                            lambda **k: self._base_result())
        monkeypatch.setattr(updates, 'fetch_expected_sha256',
                            lambda url, name: 'e' * 64)
        monkeypatch.setattr(updates, 'download_update',
                            lambda *a, **k: installed.append('dl'))
        monkeypatch.setattr(updates, 'install_update',
                            lambda p, **k: installed.append('install'))
        self._enable_auto(app, (datetime.now().hour + 2) % 24)
        with app.app_context():
            updates.scheduled_update_check()
        assert installed == []


class TestUpdateSettingsApi:
    URL = '/api/v2/system/updates/settings'

    def test_defaults(self, auth_client, clean_update_config):
        r = auth_client.get(self.URL)
        assert r.status_code == 200
        data = json.loads(r.data)['data']
        assert data['channel'] == 'stable'
        assert data['auto_install'] is False
        assert data['hour'] == 3

    def test_roundtrip(self, auth_client, clean_update_config):
        r = auth_client.patch(
            self.URL,
            data=json.dumps({'channel': 'rc', 'auto_install': True, 'hour': 0}),
            content_type='application/json')
        assert r.status_code == 200, r.data[:300]
        data = json.loads(auth_client.get(self.URL).data)['data']
        assert data == {**data, 'channel': 'rc', 'auto_install': True, 'hour': 0}

    def test_validation(self, auth_client, clean_update_config):
        for payload in ({'channel': 'nightly'}, {'hour': 24}, {'hour': 'three'},
                        {'auto_install': 'yes'}):
            r = auth_client.patch(self.URL, data=json.dumps(payload),
                                  content_type='application/json')
            assert r.status_code == 400, payload

    def test_requires_admin(self, client, clean_update_config):
        assert client.get(self.URL).status_code in (401, 403)
