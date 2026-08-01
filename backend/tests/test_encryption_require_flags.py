"""
Regression tests for the #245 follow-up: the two opt-in refuse-to-run flags
must actually refuse, loudly, and must not change behavior when unset.

  - ``UCM_REQUIRE_DB_ENCRYPTION_KEY`` (utils.encryption): the check only
    fired on the first cipher use, which every caller reaches lazily — so a
    deployment that set the flag without a key BOOTED NORMALLY, and
    ``decrypt_value()`` swallowed the refusal into a silent ``None`` (every
    integration secret read back as "no value"). Now: the module refuses at
    import time (utils.encryption is imported during startup via
    ``models.hsm`` → ``models/__init__``), and a configuration refusal
    propagates out of ``decrypt_value()``.

  - ``UCM_REQUIRE_KEY_ENCRYPTION`` (security.encryption): only consulted in
    the no-key branch of ``_initialize()``; an existing-but-invalid
    ``/etc/ucm/master.key`` (or a bad ``KEY_ENCRYPTION_KEY``) fell back to
    ``_enabled = False`` and private keys were written to the database in
    PLAINTEXT despite the flag. Now: an invalid key is as fatal as a
    missing one.

  - ``POST /api/v2/system/security/disable-encryption`` refuses up front
    under the flag, instead of decrypting the database and removing the key
    file and only then blowing up in ``reload()`` — which left plaintext
    keys AND a service that refuses its next startup.

Both flags accept the codebase's usual truthy spellings ('1', 'true',
'yes', 'on'), matching security.rate_limiter._get_env_bool.

CRITICAL: with NEITHER flag set, behavior must be exactly what shipped
before — the tests below pin that too.
"""
import importlib
import json
import sys

import pytest
from cryptography.fernet import Fernet

DB_FLAG = 'UCM_REQUIRE_DB_ENCRYPTION_KEY'
KEY_FLAG = 'UCM_REQUIRE_KEY_ENCRYPTION'

# A well-formed Fernet token encrypted under some OTHER key — decrypting it
# with any test cipher is a GENUINE decryption failure (wrong key), which
# must keep returning None.
FOREIGN_TOKEN = Fernet(Fernet.generate_key()).encrypt(b'foreign').decode()


@pytest.fixture
def clean_env():
    """MonkeyPatch with both flags and both key vars cleared; restores the
    ambient module state (cipher cache, KeyEncryption singleton) on exit so
    the session-scoped app fixture used by other test files is unaffected."""
    mp = pytest.MonkeyPatch()
    for var in (DB_FLAG, KEY_FLAG, 'UCM_DB_ENCRYPTION_KEY', 'KEY_ENCRYPTION_KEY'):
        mp.delenv(var, raising=False)
    yield mp
    mp.undo()
    import utils.encryption as db_enc
    db_enc.get_cipher.cache_clear()
    from security import encryption as key_enc
    try:
        key_enc.KeyEncryption().reload()
    except RuntimeError:
        pass


def _fresh_import_utils_encryption():
    """Import utils.encryption the way startup does (models.hsm), executing
    its module body fresh. Always restores the previously-loaded module
    object afterwards so references held elsewhere stay consistent."""
    saved = sys.modules.pop('utils.encryption', None)
    try:
        return importlib.import_module('utils.encryption')
    finally:
        if saved is not None:
            sys.modules['utils.encryption'] = saved
            setattr(sys.modules['utils'], 'encryption', saved)


# ---------------------------------------------------------------------------
# UCM_REQUIRE_DB_ENCRYPTION_KEY — startup refusal (finding 1)
# ---------------------------------------------------------------------------

class TestRequireDbEncryptionKeyStartup:
    """The flag must refuse at import time, i.e. before create_app returns."""

    def test_flag_set_without_key_refuses_import(self, clean_env):
        clean_env.setenv(DB_FLAG, 'true')
        with pytest.raises(RuntimeError, match='refusing to start'):
            _fresh_import_utils_encryption()

    @pytest.mark.parametrize('spelling', ['1', 'yes', 'on', 'TRUE', ' true '])
    def test_flag_truthy_spellings_refuse(self, clean_env, spelling):
        """House opt-in pattern: ('1', 'true', 'yes', 'on'), case/space
        insensitive — not just the literal string 'true'."""
        clean_env.setenv(DB_FLAG, spelling)
        with pytest.raises(RuntimeError):
            _fresh_import_utils_encryption()

    def test_flag_set_with_key_boots_and_round_trips(self, clean_env):
        clean_env.setenv(DB_FLAG, 'true')
        clean_env.setenv('UCM_DB_ENCRYPTION_KEY', Fernet.generate_key().decode())
        mod = _fresh_import_utils_encryption()
        assert mod.decrypt_value(mod.encrypt_value('s3cret')) == 's3cret'

    @pytest.mark.parametrize('bad_key', [
        'a3f1' * 16,                          # openssl rand -hex 32 (64 hex chars)
        Fernet.generate_key().decode()[:20],  # truncated / mangled key
    ], ids=['hex-key', 'truncated-key'])
    def test_flag_set_with_unusable_key_refuses_import(self, clean_env, bad_key):
        """Presence is not usability: a key that is set but does not parse
        must be as fatal at startup as a missing one, mirroring the sibling
        UCM_REQUIRE_KEY_ENCRYPTION. Otherwise a hex key — exactly what
        `openssl rand -hex 32` produces — boots fine, and the model-layer
        encrypted-property setters swallow the first-use ValueError into
        PLAINTEXT secret writes (models/sso.py, models/email_notification.py)."""
        clean_env.setenv(DB_FLAG, 'true')
        clean_env.setenv('UCM_DB_ENCRYPTION_KEY', bad_key)
        with pytest.raises(RuntimeError, match='refusing to start'):
            _fresh_import_utils_encryption()

    def test_flag_unset_boots_without_key(self, clean_env):
        """COMPATIBILITY: deployments that set neither flag must import
        (start up) exactly as before, with no key configured at all."""
        mod = _fresh_import_utils_encryption()
        assert hasattr(mod, 'get_cipher')

    def test_falsy_values_do_not_refuse(self, clean_env):
        for spelling in ('', '0', 'false', 'off', 'no'):
            clean_env.setenv(DB_FLAG, spelling)
            _fresh_import_utils_encryption()  # must not raise


# ---------------------------------------------------------------------------
# decrypt_value must not swallow a configuration refusal (finding 1)
# ---------------------------------------------------------------------------

class TestDecryptValueRefusalIsLoud:

    def test_decrypt_value_raises_under_flag_without_key(self, clean_env):
        """A refusal must never be indistinguishable from "no value": before
        the fix this returned None with zero log output."""
        import utils.encryption as mod
        clean_env.setenv(DB_FLAG, 'true')
        mod.get_cipher.cache_clear()
        with pytest.raises(RuntimeError, match=DB_FLAG):
            mod.decrypt_value(FOREIGN_TOKEN)

    def test_encrypt_value_raises_under_flag_without_key(self, clean_env):
        import utils.encryption as mod
        clean_env.setenv(DB_FLAG, 'true')
        mod.get_cipher.cache_clear()
        with pytest.raises(RuntimeError, match=DB_FLAG):
            mod.encrypt_value('anything')

    def test_genuine_decrypt_failure_still_returns_none(self, clean_env):
        """COMPATIBILITY: with a working cipher, corrupted data / wrong key
        keeps returning None exactly as before."""
        import utils.encryption as mod
        clean_env.setenv('UCM_DB_ENCRYPTION_KEY', Fernet.generate_key().decode())
        mod.get_cipher.cache_clear()
        assert mod.decrypt_value(FOREIGN_TOKEN) is None
        assert mod.decrypt_value('gAAAAA' + 'x' * 60) is None

    def test_no_flag_no_key_fallback_still_returns_none_on_bad_token(self, clean_env):
        """COMPATIBILITY: no flag, no key — the machine-id fallback cipher is
        built silently (a warning is logged since #245) and a bad token is
        still a quiet None."""
        import utils.encryption as mod
        mod.get_cipher.cache_clear()
        assert mod.decrypt_value(FOREIGN_TOKEN) is None

    def test_no_flag_no_key_round_trip_unchanged(self, clean_env):
        """COMPATIBILITY: existing deployments' machine-derived key keeps
        encrypting and decrypting."""
        import utils.encryption as mod
        mod.get_cipher.cache_clear()
        assert mod.decrypt_value(mod.encrypt_value('legacy')) == 'legacy'

    def test_empty_values_pass_through(self, clean_env):
        import utils.encryption as mod
        clean_env.setenv(DB_FLAG, 'true')  # even under the flag
        assert mod.decrypt_value('') == ''
        assert mod.decrypt_value(None) is None


# ---------------------------------------------------------------------------
# UCM_REQUIRE_KEY_ENCRYPTION — invalid key must not bypass the flag (finding 2)
# ---------------------------------------------------------------------------

class TestRequireKeyEncryptionInvalidKey:

    def test_invalid_master_key_file_refuses_under_flag(self, clean_env, tmp_path):
        from security import encryption as enc_mod
        bad_key = tmp_path / 'master.key'
        bad_key.write_text('not-a-valid-fernet-key\n')
        clean_env.setattr(enc_mod, 'MASTER_KEY_PATH', bad_key)
        clean_env.setenv(KEY_FLAG, 'true')
        with pytest.raises(RuntimeError, match='invalid'):
            enc_mod.KeyEncryption().reload()

    def test_truncated_master_key_file_refuses_under_flag(self, clean_env, tmp_path):
        from security import encryption as enc_mod
        truncated = tmp_path / 'master.key'
        truncated.write_text(Fernet.generate_key().decode()[:20])
        clean_env.setattr(enc_mod, 'MASTER_KEY_PATH', truncated)
        clean_env.setenv(KEY_FLAG, '1')  # house truthy spelling
        with pytest.raises(RuntimeError, match=KEY_FLAG):
            enc_mod.KeyEncryption().reload()

    def test_invalid_env_key_refuses_under_flag(self, clean_env, tmp_path):
        from security import encryption as enc_mod
        clean_env.setattr(enc_mod, 'MASTER_KEY_PATH', tmp_path / 'nope.key')
        clean_env.setenv('KEY_ENCRYPTION_KEY', 'garbage')
        clean_env.setenv(KEY_FLAG, 'yes')
        with pytest.raises(RuntimeError, match='invalid'):
            enc_mod.KeyEncryption().reload()

    def test_missing_key_still_refuses_under_flag(self, clean_env, tmp_path):
        """Regression guard for the behavior #245 shipped: flag + NO key."""
        from security import encryption as enc_mod
        clean_env.setattr(enc_mod, 'MASTER_KEY_PATH', tmp_path / 'nope.key')
        clean_env.setenv(KEY_FLAG, 'true')
        with pytest.raises(RuntimeError, match='no key is configured'):
            enc_mod.KeyEncryption().reload()

    def test_invalid_key_falls_back_disabled_without_flag(self, clean_env, tmp_path):
        """COMPATIBILITY: without the flag an invalid key still degrades to
        disabled (logged), and encrypt() passes data through unchanged."""
        from security import encryption as enc_mod
        bad_key = tmp_path / 'master.key'
        bad_key.write_text('not-a-valid-fernet-key\n')
        clean_env.setattr(enc_mod, 'MASTER_KEY_PATH', bad_key)
        enc_mod.KeyEncryption().reload()  # must not raise
        assert not enc_mod.KeyEncryption().is_enabled
        assert enc_mod.KeyEncryption().encrypt('QUJD') == 'QUJD'

    def test_valid_key_enables_under_flag(self, clean_env, tmp_path):
        from security import encryption as enc_mod
        good_key = tmp_path / 'master.key'
        good_key.write_text(Fernet.generate_key().decode() + '\n')
        clean_env.setattr(enc_mod, 'MASTER_KEY_PATH', good_key)
        clean_env.setenv(KEY_FLAG, 'true')
        enc_mod.KeyEncryption().reload()
        assert enc_mod.KeyEncryption().is_enabled
        secret_text = 'sample integration secret text'
        assert enc_mod.decrypt_text(enc_mod.encrypt_text(secret_text)) == secret_text


# ---------------------------------------------------------------------------
# Disable-encryption endpoint refuses up front (finding 3)
# ---------------------------------------------------------------------------

class TestDisableEncryptionRefusesUpFront:

    def test_refuses_before_any_destructive_step(self, auth_client, monkeypatch):
        from security import encryption as enc

        destructive = []
        monkeypatch.setattr(
            enc, 'decrypt_all_keys',
            lambda dry_run=True: destructive.append('decrypt') or (0, 0, []))
        monkeypatch.setattr(
            enc.KeyEncryption, 'remove_key_file',
            staticmethod(lambda: destructive.append('remove_key')))
        monkeypatch.setattr(enc.key_encryption, '_enabled', True, raising=False)
        monkeypatch.setenv(KEY_FLAG, 'true')

        r = auth_client.post('/api/v2/system/security/disable-encryption',
                             data=json.dumps({}),
                             content_type='application/json')

        assert r.status_code == 409
        body = r.get_data(as_text=True)
        assert 'UCM_REQUIRE_KEY_ENCRYPTION' in body
        assert destructive == [], (
            'disable-encryption must refuse BEFORE decrypting keys or '
            'removing the key file')

    def test_unchanged_without_flag(self, auth_client, monkeypatch):
        """COMPATIBILITY: flag unset + encryption not enabled is the same
        400 as before."""
        from security import encryption as enc
        monkeypatch.delenv(KEY_FLAG, raising=False)
        monkeypatch.setattr(enc.key_encryption, '_enabled', False, raising=False)
        r = auth_client.post('/api/v2/system/security/disable-encryption',
                             data=json.dumps({}),
                             content_type='application/json')
        assert r.status_code == 400
