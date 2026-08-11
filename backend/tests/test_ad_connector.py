"""
Tests for the ADConnectorConfig model -- encrypted-at-rest bind password
(same mechanism/pattern as models/msca.py's MicrosoftCA.password), and
fail-closed behavior when encryption is unavailable.
"""
import pytest

from models import db, ADConnectorConfig


def test_bind_password_encrypted_at_rest(app):
    with app.app_context():
        ADConnectorConfig.query.delete()
        db.session.commit()

        config = ADConnectorConfig(
            server='dc1.hagland.domain',
            base_dn='DC=hagland,DC=domain',
            bind_dn='CN=svc-ucm,CN=Users,DC=hagland,DC=domain',
            enabled=True,
        )
        config.bind_password = 'super-secret-bind-password'
        db.session.add(config)
        db.session.commit()

        # Raw column must not contain the plaintext value.
        assert config._bind_password is not None
        assert 'super-secret-bind-password' not in config._bind_password

        # Property getter must decrypt it back correctly.
        assert config.bind_password == 'super-secret-bind-password'

        # to_dict() masks by default, reveals only with include_secrets=True.
        assert config.to_dict()['bind_password'] == '***'
        assert config.to_dict(include_secrets=True)['bind_password'] == 'super-secret-bind-password'

        db.session.delete(config)
        db.session.commit()


def test_bind_password_setter_fails_closed_when_encryption_unavailable(app, monkeypatch):
    """If the encryption cipher can't be obtained, saving must raise -- not
    silently persist the credential in plaintext."""
    import utils.encryption as enc_mod

    def _broken_cipher():
        raise RuntimeError('encryption key unavailable')

    monkeypatch.setattr(enc_mod, 'get_cipher', _broken_cipher)

    with app.app_context():
        config = ADConnectorConfig(server='dc1.hagland.domain')
        with pytest.raises(RuntimeError):
            config.bind_password = 'super-secret-bind-password'
        # The setter must not have stored anything, plaintext or otherwise.
        assert config._bind_password is None


def test_get_singleton_returns_none_when_unconfigured(app):
    with app.app_context():
        ADConnectorConfig.query.delete()
        db.session.commit()
        assert ADConnectorConfig.get_singleton() is None
