"""ACME certificate profiles (draft-ietf-acme-profiles).

A profile is a named, server-advertised issuance policy. The server publishes
``meta.profiles`` (name → human description) in the directory; a client may
select one via the ``profile`` field of newOrder, and the server issues with
that profile's parameters.

Profiles are **opt-in**: with no configuration the directory advertises none
and any client-supplied ``profile`` is rejected, leaving issuance exactly as
it was before this feature existed.

Configuration lives in SystemConfig key ``acme_profiles`` as a JSON object::

    {
      "default":    {"description": "90-day server certificate",
                     "validity_days": 90, "digest": "sha256"},
      "shortlived": {"description": "7-day certificate",
                     "validity_days": 7,  "digest": "sha256"},
      "mtls":       {"description": "client certificate",
                     "validity_days": 30, "template_id": 4}
    }

``template_id`` binds a certificate template to the profile, the way a SCEP
profile binds one (#228): the template's key usage and extended key usage
then govern every certificate issued under the profile, which is the only
way an ACME client can obtain anything but the server_cert defaults, since
an order carries no template of its own (#327). Validity and digest stay
those of the profile. A template that no longer exists is simply not
applied, so a deleted template can never break finalize.

Unknown keys inside a profile are ignored, so the shape can grow later
without breaking stored configuration.
"""
import json
import logging

logger = logging.getLogger(__name__)

CONFIG_KEY = 'acme_profiles'
DEFAULT_DIGEST_KEY = 'acme_default_digest'  # server-wide fallback digest (#303)

# Issuance defaults applied when a profile omits them (and when no profile is
# selected at all) — these mirror UCM's historical ACME behaviour.
DEFAULT_VALIDITY_DAYS = 90
DEFAULT_DIGEST = 'sha256'

_MAX_NAME_LEN = 64

# EKUs a template bound to an ACME profile may not grant: an ACME client only
# proved control of a name, and sign_csr never hands these to protocol
# enrollees (its _LEAF_FORBIDDEN_EKU_OIDS and friends). Refusing them when
# the binding is saved tells the operator, instead of silently stripping
# them at finalize.
_UNBINDABLE_EKU_OIDS = frozenset({
    '1.3.6.1.5.5.7.3.9',       # OCSPSigning
    '1.3.6.1.5.5.7.3.8',       # timeStamping
    '2.5.29.37.0',             # anyExtendedKeyUsage
    '1.3.6.1.4.1.311.20.2.2',  # Microsoft Smartcard Logon
})
_ALLOWED_DIGESTS = ('sha256', 'sha384', 'sha512')
# Same hard cap as every other issuance path (see the validity-cap rule).
_MAX_VALIDITY_DAYS = 3650


def get_default_digest():
    """Server-wide signing digest for orders without a profile (#303).

    Stored in SystemConfig ``acme_default_digest``; anything absent or
    invalid falls back to the historical sha256. Profiles that omit their
    own ``digest`` inherit this value too.
    """
    from models import SystemConfig

    row = SystemConfig.query.filter_by(key=DEFAULT_DIGEST_KEY).first()
    value = (row.value or '').strip().lower() if row and row.value else ''
    return value if value in _ALLOWED_DIGESTS else DEFAULT_DIGEST


def _raw_config():
    """Return the parsed ``acme_profiles`` config, or {} when unset/invalid."""
    from models import SystemConfig

    row = SystemConfig.query.filter_by(key=CONFIG_KEY).first()
    if not row or not row.value:
        return {}
    try:
        parsed = json.loads(row.value)
    except (TypeError, ValueError) as e:
        logger.warning(f"Invalid {CONFIG_KEY} configuration: {e}")
        return {}
    if not isinstance(parsed, dict):
        logger.warning(f"{CONFIG_KEY} must be a JSON object")
        return {}
    return parsed


def _coerce_template_id(value):
    """A positive integer template id, or None (unset, 0 or unusable)."""
    if value is None or isinstance(value, bool):
        return None
    try:
        value = int(value)
    except (TypeError, ValueError):
        return None
    return value if value > 0 else None


def template_binding_error(profile_name, template_id):
    """Why *template_id* cannot be bound to an ACME profile, or None if it can."""
    if isinstance(template_id, bool) or not isinstance(template_id, int) or template_id < 1:
        return f"profile '{profile_name}': template_id must be a positive integer"
    from models import db
    from models.certificate_template import CertificateTemplate
    from services.template_service import template_extensions
    from utils.eku_validation import normalize_extra_ekus

    template = db.session.get(CertificateTemplate, template_id)
    if template is None:
        return f"profile '{profile_name}': template {template_id} not found"
    if template.template_type == 'ca':
        return f"profile '{profile_name}': CA templates cannot be bound to an ACME profile"
    ekus = template_extensions(template).get('extended_key_usage')
    if isinstance(ekus, list) and ekus:
        oids, err = normalize_extra_ekus(ekus)
        if err:
            return f"profile '{profile_name}': template has invalid EKUs: {err}"
        refused = sorted(set(oids) & _UNBINDABLE_EKU_OIDS)
        if refused:
            return (
                f"profile '{profile_name}': template EKU {', '.join(refused)} "
                "cannot be issued over ACME"
            )
    return None


def _sanitize(name, spec):
    """Normalise one profile entry, or return None when unusable."""
    if not isinstance(name, str) or not name or len(name) > _MAX_NAME_LEN:
        return None
    if not isinstance(spec, dict):
        return None

    description = spec.get('description')
    if not isinstance(description, str) or not description:
        description = name

    validity = spec.get('validity_days', DEFAULT_VALIDITY_DAYS)
    try:
        validity = int(validity)
    except (TypeError, ValueError):
        validity = DEFAULT_VALIDITY_DAYS
    if validity < 1:
        validity = DEFAULT_VALIDITY_DAYS
    if validity > _MAX_VALIDITY_DAYS:
        validity = _MAX_VALIDITY_DAYS

    digest = spec.get('digest', None)
    if not isinstance(digest, str) or digest.lower() not in _ALLOWED_DIGESTS:
        digest = get_default_digest()

    return {
        'description': description,
        'validity_days': validity,
        'digest': digest.lower(),
        'template_id': _coerce_template_id(spec.get('template_id')),
    }


def validate_config(obj):
    """Validate an operator-supplied profile map before storing it.

    Returns ``(True, None)`` or ``(False, error_message)``. Unlike the lenient
    read path (which silently drops bad entries so a bad row can never break
    issuance), writes are strict so the operator gets told what is wrong.
    """
    if not isinstance(obj, dict):
        return False, 'profiles must be an object'
    if len(obj) > 50:
        return False, 'too many profiles (max 50)'

    for name, spec in obj.items():
        if not isinstance(name, str) or not name:
            return False, 'profile names must be non-empty strings'
        if len(name) > _MAX_NAME_LEN:
            return False, f"profile name '{name[:20]}…' is too long (max {_MAX_NAME_LEN})"
        if not isinstance(spec, dict):
            return False, f"profile '{name}' must be an object"

        description = spec.get('description')
        if description is not None and not isinstance(description, str):
            return False, f"profile '{name}': description must be a string"
        if isinstance(description, str) and len(description) > 255:
            return False, f"profile '{name}': description too long (max 255)"

        if 'validity_days' in spec:
            try:
                validity = int(spec['validity_days'])
            except (TypeError, ValueError):
                return False, f"profile '{name}': validity_days must be an integer"
            if validity < 1 or validity > _MAX_VALIDITY_DAYS:
                return False, (
                    f"profile '{name}': validity_days must be between 1 "
                    f"and {_MAX_VALIDITY_DAYS}"
                )

        if 'digest' in spec:
            digest = spec['digest']
            if not isinstance(digest, str) or digest.lower() not in _ALLOWED_DIGESTS:
                return False, (
                    f"profile '{name}': digest must be one of "
                    f"{', '.join(_ALLOWED_DIGESTS)}"
                )

        if spec.get('template_id') is not None:
            err = template_binding_error(name, spec['template_id'])
            if err:
                return False, err

    return True, None


def get_profiles():
    """Return {name: {description, validity_days, digest, template_id}} for valid profiles."""
    profiles = {}
    for name, spec in _raw_config().items():
        clean = _sanitize(name, spec)
        if clean is not None:
            profiles[name] = clean
    return profiles


def directory_meta():
    """Return the ``meta.profiles`` map (name → description), or {} if none.

    Per the draft, the directory advertises the profile names a client may
    request together with a human-readable description.
    """
    return {name: spec['description'] for name, spec in get_profiles().items()}


def is_known(name):
    """Whether ``name`` is a currently advertised profile."""
    return isinstance(name, str) and name in get_profiles()


def issuance_params(name):
    """Issuance parameters for a profile name.

    Falls back to UCM's historical defaults when the profile is absent (e.g.
    the order predates a config change, or no profile was selected), so a
    finalize can never fail because a profile was removed after the order.
    """
    profile = get_profiles().get(name) if name else None
    if not profile:
        return {
            'validity_days': DEFAULT_VALIDITY_DAYS,
            'digest': get_default_digest(),
            'template_id': None,
        }
    return {
        'validity_days': profile['validity_days'],
        'digest': profile['digest'],
        'template_id': profile.get('template_id'),
    }
