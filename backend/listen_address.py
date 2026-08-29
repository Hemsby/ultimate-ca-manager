"""Listen address helpers shared by gunicorn, the HTTP protocol server and
the development server.

The address UCM listens on comes from the ``HOST`` environment variable
(``/etc/ucm/ucm.env`` on DEB/RPM, the container environment on Docker):

    HOST=0.0.0.0    IPv4 only (default)
    HOST=::         IPv6 and IPv4 (dual-stack, IPv4 peers show up as
                    ``::ffff:a.b.c.d`` on the socket)
    HOST=<address>  one specific interface address

This module has no Flask dependency on purpose: ``gunicorn_config.py``
imports it before the application exists.
"""
import ipaddress
import os
import sys

DEFAULT_BIND_HOST = '0.0.0.0'


def get_bind_host(default: str = DEFAULT_BIND_HOST) -> str:
    """Return the validated ``HOST`` value, or *default* when unset/invalid."""
    raw = (os.getenv('HOST') or '').strip()
    if not raw:
        return default
    try:
        ipaddress.ip_address(raw)
    except ValueError:
        print(f"HOST={raw!r} is not an IP address, listening on {default}",
              file=sys.stderr)
        return default
    return raw


def format_bind(host: str, port) -> str:
    """gunicorn ``bind`` string: IPv6 addresses need brackets."""
    return f"[{host}]:{port}" if ':' in host else f"{host}:{port}"


def normalize_peer_address(addr):
    """Map an IPv4-mapped IPv6 peer (``::ffff:192.0.2.1``) back to plain IPv4.

    Any other value (plain IPv4, real IPv6, empty, garbage) is returned
    unchanged.
    """
    if not addr or ':' not in addr:
        return addr
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return addr
    mapped = getattr(ip, 'ipv4_mapped', None)
    return str(mapped) if mapped is not None else addr


class PeerAddressNormalizer:
    """WSGI middleware rewriting an IPv4-mapped ``REMOTE_ADDR`` to plain IPv4.

    When the server listens dual-stack (``HOST=::``) every IPv4 client is
    reported as ``::ffff:a.b.c.d``. Trusted-proxy sets, the LAN rate-limit
    exemption, loopback checks and audit logs all compare or parse that
    value as an IPv4 address, so it is normalized once here, before
    ProxyFix records the original peer.
    """

    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        addr = environ.get('REMOTE_ADDR')
        if addr:
            normalized = normalize_peer_address(addr)
            if normalized != addr:
                environ['REMOTE_ADDR'] = normalized
        return self.app(environ, start_response)
