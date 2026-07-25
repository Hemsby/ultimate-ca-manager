"""
Parses an incoming MS-XCEP ``GetPolicies`` SOAP envelope.

Untrusted input straight off the wire, so parsing goes through
``defusedxml``'s lxml entry point (same pattern as
``services/wstep/rst_parser.py`` and ``api/v2/sso/__init__.py``) rather
than raw ``lxml.etree.fromstring``, to guard against XXE / entity
expansion.
"""
from dataclasses import dataclass

from defusedxml.lxml import fromstring as safe_fromstring

from services.wstep.soap_envelope import ADDRESSING_NS, SOAP_NS, WSSE_NS


class GetPoliciesParseError(Exception):
    """Raised for a malformed GetPolicies envelope."""


@dataclass
class ParsedGetPolicies:
    message_id: str | None
    # wsse:Security header element (lxml), if present — carries the
    # UsernameToken for the UsernamePassword binding. None if the client
    # sent no WS-Security header at all (e.g. relying on HTTP Basic
    # instead, which this endpoint also still accepts as a fallback).
    security_header: object


def parse_get_policies(envelope_bytes):
    try:
        root = safe_fromstring(envelope_bytes)
    except Exception as e:
        raise GetPoliciesParseError(f'Malformed XML: {e}')

    message_id_el = root.find(f'.//{{{ADDRESSING_NS}}}MessageID')
    message_id = message_id_el.text.strip() if message_id_el is not None and message_id_el.text else None

    security_header = root.find(f'.//{{{SOAP_NS}}}Header/{{{WSSE_NS}}}Security')

    return ParsedGetPolicies(message_id=message_id, security_header=security_header)
