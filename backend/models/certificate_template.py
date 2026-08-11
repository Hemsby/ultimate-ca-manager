"""
Certificate Template Model
Pre-configured certificate profiles for common use cases
"""
from datetime import datetime
from models import db
from utils.datetime_utils import utc_now, utc_isoformat


class CertificateTemplate(db.Model):
    """Certificate Template for pre-configured certificate profiles"""
    __tablename__ = "certificate_templates"
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False, index=True)
    description = db.Column(db.Text)
    template_type = db.Column(db.String(50), nullable=False)  # web_server, email, vpn_server, vpn_client, code_signing, client_auth, piv, custom
    
    # Key configuration
    key_type = db.Column(db.String(20), default='RSA-2048')  # RSA-2048, RSA-4096, EC-P256, EC-P384
    validity_days = db.Column(db.Integer, default=397)
    digest = db.Column(db.String(20), default='sha256')
    
    # DN Template (JSON) - Can use variables like {username}, {email}, {hostname}
    # Example: {"CN": "{hostname}", "O": "My Company", "OU": "IT"}
    dn_template = db.Column(db.Text)
    
    # Extensions Template (JSON)
    # Example: {
    #   "key_usage": ["digitalSignature", "keyEncipherment"],
    #   "extended_key_usage": ["serverAuth"],
    #   "basic_constraints": {"ca": false},
    #   "san_types": ["dns", "ip"]  # Which SAN types to show in UI
    # }
    extensions_template = db.Column(db.Text, nullable=False)
    
    # Flags
    is_system = db.Column(db.Boolean, default=False)  # System templates can't be deleted
    is_active = db.Column(db.Boolean, default=True)

    # Build the subject/SAN from the requester's Active Directory object
    # (via the AD Connector) instead of the CSR's own, for naked CSRs real
    # Windows GPO autoenrollment submits -- the per-template opt-in
    # mirroring real ADCS's own msPKI-Certificate-Name-Flag configurability
    # (see services/wstep/wstep_service.py's issue()).
    ad_derived_subject = db.Column(db.Boolean, default=False)

    # Whether MS-XCEP's GetPolicies advertises autoEnroll=true for this
    # template -- real ADCS's Enroll and Autoenroll are two separate ACL
    # permission bits (Enroll lets a principal manually request a cert;
    # Autoenroll is required on top of that before unattended background
    # autoenrollment will pick the template up at all). Without this,
    # every active template got offered for autoenrollment to every
    # Kerberos-authenticated principal at logon, not just the ones meant
    # for it. Defaults false, matching how real templates default to
    # Enroll-broadly/Autoenroll-narrowly.
    autoenroll_enabled = db.Column(db.Boolean, default=False)

    # Optional Enroll ACL gate: an AD group (DN or sAMAccountName) that the
    # authenticated Kerberos principal must belong to before WSTEP will
    # issue against this template. Unset (default) means no restriction --
    # matches real ADCS's own default "any authenticated member can enroll"
    # behavior. Only enforced on the Kerberos-bound CES path, since the
    # UsernamePassword path has no per-request principal to check (a single
    # shared SystemConfig credential, not a UCM/AD account) -- see
    # services/wstep/wstep_service.py's issue().
    allowed_ad_group = db.Column(db.String(255))

    # Metadata
    created_at = db.Column(db.DateTime, default=utc_now)
    created_by = db.Column(db.String(80))
    updated_at = db.Column(db.DateTime, onupdate=utc_now)
    updated_by = db.Column(db.String(80))
    
    def to_dict(self):
        """Convert to dictionary"""
        import json
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "template_type": self.template_type,
            "key_type": self.key_type,
            "validity_days": self.validity_days,
            "digest": self.digest,
            "dn_template": json.loads(self.dn_template) if self.dn_template else {},
            "extensions_template": json.loads(self.extensions_template) if self.extensions_template else {},
            "is_system": self.is_system,
            "is_active": self.is_active,
            "ad_derived_subject": bool(self.ad_derived_subject),
            "autoenroll_enabled": bool(self.autoenroll_enabled),
            "allowed_ad_group": self.allowed_ad_group,
            "created_at": utc_isoformat(self.created_at),
            "created_by": self.created_by,
            "updated_at": utc_isoformat(self.updated_at),
            "updated_by": self.updated_by,
        }
