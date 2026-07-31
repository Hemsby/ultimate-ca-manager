"""Challenge validation mixin for ACME service"""
import json
import hashlib
import base64
import logging

from models import db
from models.acme_models import AcmeChallenge, AcmeAuthorization
from utils.datetime_utils import utc_now

logger = logging.getLogger(__name__)


class ChallengeMixin:
    def validate_http01_challenge(
        self,
        challenge: AcmeChallenge,
        account
    ) -> bool:
        """Validate HTTP-01 challenge
        
        Args:
            challenge: AcmeChallenge object
            account: AcmeAccount object for key authorization
            
        Returns:
            True if validation successful
        """
        import requests
        
        # Get identifier from authorization
        auth = challenge.authorization
        identifier_value = auth.identifier_value if auth else ""
        identifier_type = auth.identifier_type if auth else "dns"
        
        # Compute key authorization
        key_authz = self._compute_key_authorization(
            challenge.token,
            account.jwk_thumbprint
        )
        
        # Fetch from well-known URL
        # RFC 8738: For IP identifiers, use the IP directly as host.
        # RFC 3986: IPv6 literals MUST be bracketed in the URL.
        if identifier_type == "ip":
            from utils.acme_ip import format_ip_for_url
            url_host = format_ip_for_url(identifier_value)
        else:
            url_host = identifier_value
        url = f"http://{url_host}/.well-known/acme-challenge/{challenge.token}"
        
        try:
            allow_private = self._acme_allow_private_ips()

            # Cloud metadata is NEVER a legitimate challenge target, so this
            # check is unconditional — the same narrow deny-list the rest of
            # UCM applies to admin-supplied URLs. Without it, the default
            # configuration (private IPs allowed, for on-prem issuance) still
            # fetched challenges from 169.254.169.254 and friends.
            # allow_loopback follows the private-IP setting: a client colocated
            # on 127.0.0.1 is a legitimate on-prem case, an IMDS endpoint never is.
            from utils.ssrf_protection import validate_url_not_cloud_metadata
            try:
                validate_url_not_cloud_metadata(url, allow_loopback=allow_private)
            except ValueError as md_err:
                self._invalidate_challenge(
                    challenge,
                    'rejectedIdentifier',
                    'Identifier targets a forbidden address',
                )
                db.session.commit()
                logger.warning(f"HTTP-01 SSRF blocked for {identifier_value}: {md_err}")
                return False

            # SSRF protection: reject identifiers that are (or resolve to)
            # private/loopback/link-local addresses unless explicitly allowed
            # (local ACME is meant for internal infra).
            # RFC 8738 IP identifiers are checked too: validate_host_not_private
            # handles a literal IP directly, and skipping them here let an
            # external client aim a challenge fetch at 127.0.0.1 or the cloud
            # metadata service even with private IPs disallowed.
            pinned_ip = None
            if not allow_private:
                from utils.ssrf_protection import validate_host_not_private
                try:
                    pinned_ip = validate_host_not_private(identifier_value)
                except ValueError as ssrf_err:
                    self._invalidate_challenge(
                        challenge,
                        'rejectedIdentifier',
                        'Identifier resolves to a non-public address',
                    )
                    db.session.commit()
                    logger.warning(f"HTTP-01 SSRF blocked for {identifier_value}: {ssrf_err}")
                    return False

            if pinned_ip is not None and identifier_type != "ip":
                # Close the DNS-rebinding window: the guard resolved the name,
                # and requests would resolve it again — a short-TTL record can
                # answer public for the check and private for the fetch. Pin the
                # connection to the address that was actually validated.
                # Known limitation: only the hardened (allow_private_ips=false)
                # configuration is pinned. Under the default, private addresses
                # are a legitimate answer anyway, so pinning would buy only the
                # metadata check above at the cost of collapsing every on-prem
                # validation onto a single address (no dual-stack failover).
                from utils.ssrf_protection import pin_host
                with pin_host(identifier_value, pinned_ip):
                    response = requests.get(url, timeout=10, allow_redirects=False)
            else:
                response = requests.get(url, timeout=10, allow_redirects=False)
            response.raise_for_status()
            
            if response.text.strip() == key_authz:
                challenge.status = "valid"
                challenge.validated = utc_now()
                
                # Update authorization status
                self._update_authorization_status(auth)
                
                db.session.commit()
                return True
            else:
                self._invalidate_challenge(
                    challenge,
                    'incorrectResponse',
                    'Key authorization mismatch',
                )
                db.session.commit()
                return False

        except Exception as e:
            self._invalidate_challenge(challenge, 'connection', str(e))
            try:
                db.session.commit()
            except Exception as commit_err:
                db.session.rollback()
                logger.error(f"DB commit failed: {commit_err}")
                raise
            return False
    
    def validate_dns01_challenge(
        self,
        challenge: AcmeChallenge,
        account
    ) -> bool:
        """Validate DNS-01 challenge
        
        Args:
            challenge: AcmeChallenge object
            account: AcmeAccount object
            
        Returns:
            True if validation successful
        """
        import dns.resolver
        
        # Get identifier from authorization
        auth = challenge.authorization
        domain = auth.identifier_value if auth else ""
        if domain.startswith('*.'):
            domain = domain[2:]
        
        # Compute key authorization
        key_authz = self._compute_key_authorization(
            challenge.token,
            account.jwk_thumbprint
        )
        
        # Compute DNS TXT record value
        txt_value = base64.urlsafe_b64encode(
            hashlib.sha256(key_authz.encode()).digest()
        ).decode().rstrip('=')
        
        # Query DNS
        txt_record = f"_acme-challenge.{domain}"
        
        try:
            # Optional override: allow operators to point DNS-01 validation at
            # a specific authoritative resolver (e.g. an internal BIND9 fed by
            # cert-manager rfc2136) regardless of the system /etc/resolv.conf.
            # Comma-separated list in SystemConfig key ``acme.dns01_nameservers``.
            custom_ns = self._acme_dns01_nameservers()
            if custom_ns:
                resolver = dns.resolver.Resolver(configure=False)
                resolver.nameservers = custom_ns
                resolver.timeout = 5
                resolver.lifetime = 10
                answers = resolver.resolve(txt_record, 'TXT')
            else:
                answers = dns.resolver.resolve(txt_record, 'TXT')
            
            for rdata in answers:
                # RFC 8555 §8.4: TXT record content must EQUAL the key authorization hash.
                # dnspython TXT records expose .strings as a list of bytes per quoted-string segment.
                matched = False
                try:
                    for s in rdata.strings:
                        if s.decode('utf-8', errors='replace') == txt_value:
                            matched = True
                            break
                except AttributeError:
                    # Fallback (non-TXT or unusual rdata): exact string compare
                    matched = (str(rdata).strip('"') == txt_value)
                
                if matched:
                    challenge.status = "valid"
                    challenge.validated = utc_now()
                    
                    # Update authorization status
                    self._update_authorization_status(auth)
                    
                    db.session.commit()
                    return True
            
            # No matching TXT record found
            self._invalidate_challenge(
                challenge,
                'incorrectResponse',
                f'No matching TXT record found at {txt_record}',
            )
            db.session.commit()
            return False

        except Exception as e:
            self._invalidate_challenge(challenge, 'dns', str(e))
            try:
                db.session.commit()
            except Exception as commit_err:
                db.session.rollback()
                logger.error(f"DB commit failed: {commit_err}")
                raise
            return False
    
    def validate_tls_alpn01_challenge(
        self,
        challenge: AcmeChallenge,
        account
    ) -> bool:
        """Validate TLS-ALPN-01 challenge (RFC 8737, RFC 8738)
        
        Connects to the domain/IP on port 443 with the acme-tls/1 ALPN extension,
        verifies the self-signed certificate contains the acmeIdentifier extension
        with the correct key authorization hash.
        
        RFC 8738: For IP identifiers, use reverse PTR mapping as SNI HostName.
        
        Args:
            challenge: AcmeChallenge object
            account: AcmeAccount object
            
        Returns:
            True if validation successful
        """
        import ssl
        import socket
        
        auth = challenge.authorization
        identifier_value = auth.identifier_value if auth else ""
        identifier_type = auth.identifier_type if auth else "dns"
        
        # Compute key authorization hash
        key_authz = self._compute_key_authorization(
            challenge.token,
            account.jwk_thumbprint
        )
        expected_hash = hashlib.sha256(key_authz.encode()).digest()
        
        try:
            allow_private = self._acme_allow_private_ips()

            # Unconditional cloud-metadata check, as in the HTTP-01 path above.
            # TLS-ALPN-01 has no URL of its own, so the authority is synthesized
            # for the shared helper (format_ip_for_url brackets an IPv6 literal
            # and returns a DNS name untouched).
            from utils.acme_ip import format_ip_for_url
            from utils.ssrf_protection import validate_url_not_cloud_metadata
            try:
                validate_url_not_cloud_metadata(
                    f"https://{format_ip_for_url(identifier_value)}/",
                    allow_loopback=allow_private,
                )
            except ValueError as md_err:
                self._invalidate_challenge(
                    challenge,
                    'rejectedIdentifier',
                    'Identifier targets a forbidden address',
                )
                db.session.commit()
                logger.warning(f"TLS-ALPN-01 SSRF blocked for {identifier_value}: {md_err}")
                return False

            # SSRF protection: see the HTTP-01 path above — IP identifiers are
            # checked as well, so an "ip" order cannot be used to reach
            # loopback/link-local/metadata addresses.
            pinned_ip = None
            if not allow_private:
                from utils.ssrf_protection import validate_host_not_private
                try:
                    pinned_ip = validate_host_not_private(identifier_value)
                except ValueError as ssrf_err:
                    self._invalidate_challenge(
                        challenge,
                        'rejectedIdentifier',
                        'Identifier resolves to a non-public address',
                    )
                    db.session.commit()
                    logger.warning(f"TLS-ALPN-01 SSRF blocked for {identifier_value}: {ssrf_err}")
                    return False

            # RFC 8738: For IP identifiers, use reverse PTR mapping as SNI
            if identifier_type == "ip":
                from utils.acme_ip import ip_to_reverse_ptr
                sni_hostname = ip_to_reverse_ptr(identifier_value)
                if not sni_hostname:
                    raise ValueError(f"Invalid IP address for TLS-ALPN-01: {identifier_value}")
            else:
                sni_hostname = identifier_value
            
            # Create SSL context with acme-tls/1 ALPN
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_alpn_protocols(['acme-tls/1'])
            
            # Connect to domain/IP. pin_host() is a urllib3 hook and does not
            # cover a raw socket, so connect straight to the address the guard
            # validated (same DNS-rebinding window as HTTP-01). The SNI name is
            # already decoupled below, and check_hostname is off.
            connect_host = pinned_ip if pinned_ip is not None else identifier_value
            with socket.create_connection((connect_host, 443), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=sni_hostname) as ssock:
                    # Verify ALPN was negotiated
                    negotiated = ssock.selected_alpn_protocol()
                    if negotiated != 'acme-tls/1':
                        raise ValueError(f"ALPN negotiation failed: {negotiated}")
                    
                    # Get peer certificate
                    cert_der = ssock.getpeercert(binary_form=True)
                    if not cert_der:
                        raise ValueError("No certificate presented")
                    
                    # Parse certificate and check acmeIdentifier extension
                    from cryptography import x509 as x509_mod
                    from cryptography.hazmat.backends import default_backend
                    cert = x509_mod.load_der_x509_certificate(cert_der, default_backend())
                    
                    # acmeIdentifier OID: 1.3.6.1.5.5.7.1.31
                    acme_id_oid = x509_mod.ObjectIdentifier("1.3.6.1.5.5.7.1.31")
                    
                    try:
                        ext = cert.extensions.get_extension_for_oid(acme_id_oid)
                        # RFC 8737 §3: the acmeIdentifier extension MUST be
                        # marked critical. Reject otherwise — accepting a
                        # non-critical extension lets a misissued cert pass.
                        if not ext.critical:
                            raise ValueError(
                                "acmeIdentifier extension is not marked critical (RFC 8737 §3)"
                            )
                        # UnrecognizedExtension.value returns raw DER bytes directly
                        ext_value = ext.value.value
                        # DER-encoded: OCTET STRING tag (0x04) + length (0x20=32)
                        if len(ext_value) > 2 and ext_value[0] == 0x04:
                            # Skip the outer OCTET STRING wrapper
                            actual_hash = ext_value[2:]
                        else:
                            actual_hash = ext_value
                        
                        if actual_hash == expected_hash:
                            challenge.status = "valid"
                            challenge.validated = utc_now()
                            self._update_authorization_status(auth)
                            db.session.commit()
                            return True
                        else:
                            raise ValueError("acmeIdentifier hash mismatch")
                    except x509_mod.ExtensionNotFound:
                        raise ValueError("Certificate missing acmeIdentifier extension")
        
        except Exception as e:
            self._invalidate_challenge(challenge, 'tls', str(e))
            try:
                db.session.commit()
            except Exception as commit_err:
                db.session.rollback()
                logger.error(f"DB commit failed: {commit_err}")
                raise
            return False
    
    def _invalidate_challenge(
        self,
        challenge: AcmeChallenge,
        error_type: str,
        detail: str,
    ) -> None:
        """Propagate a failed challenge through its authorization and order."""
        problem = {
            'type': f'urn:ietf:params:acme:error:{error_type}',
            'detail': detail,
        }
        challenge.status = 'invalid'
        challenge.error = json.dumps(problem)

        authorization = challenge.authorization
        if authorization is None:
            return
        authorization.status = 'invalid'

        order = authorization.order
        if order is not None:
            if order.status in ('pending', 'ready'):
                order.status = 'invalid'
            if order.status == 'invalid':
                self._set_order_authorization_error(order, problem)

    def _update_authorization_status(self, auth: AcmeAuthorization):
        """Update authorization status based on challenges
        
        Args:
            auth: AcmeAuthorization object
        """
        # Check if any challenge is valid
        valid_challenges = [c for c in auth.challenges if c.status == "valid"]
        
        if valid_challenges:
            auth.status = "valid"
            
            # Standalone pre-authorizations have no parent order.
            order = auth.order
            if order is None:
                return

            # Update order status if all authorizations are valid
            all_valid = all(a.status == "valid" for a in order.authorizations)
            
            if all_valid:
                order.status = "ready"
                try:
                    db.session.commit()
                except Exception as e:
                    db.session.rollback()
                    logger.error(f"DB commit failed: {e}")
                    raise
