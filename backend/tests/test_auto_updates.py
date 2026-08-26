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
                            lambda p: installed.append('install'))
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
                            lambda p: calls.append(('install', p)))
        self._enable_auto(app, datetime.now().hour)
        with app.app_context():
            updates.scheduled_update_check()
            # second tick in the same window: one attempt per version only
            updates.scheduled_update_check()
        assert calls == [('download', 'e' * 64), ('install', '/tmp/p.deb')]

    def test_refuses_install_without_checksum(self, app, clean_update_config, monkeypatch):
        from datetime import datetime
        installed = []
        monkeypatch.setattr(updates, 'check_for_updates',
                            lambda **k: self._base_result(checksum_url=None))
        monkeypatch.setattr(updates, 'download_update',
                            lambda *a, **k: installed.append('dl'))
        monkeypatch.setattr(updates, 'install_update',
                            lambda p: installed.append('install'))
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
                            lambda p: installed.append('install'))
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
