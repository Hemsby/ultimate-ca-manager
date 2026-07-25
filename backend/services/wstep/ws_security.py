"""
WS-Security XML-DSig verification for MS-WSTEP's Certificate-bound
renewal binding.

A real Windows CES client configured for Certificate authentication signs
the RST itself using its current certificate's private key (structure
confirmed via the MS-MDE2 RequestSecurityToken example in the Microsoft
Open Specifications): a ``wsse:Security`` header containing a
``wsse:BinarySecurityToken`` (the signing certificate) and a
``ds:Signature`` whose ``KeyInfo`` references that token.

This module verifies the *cryptographic* signature only — it proves the
sender possesses the private key matching the embedded certificate. It
does **not** decide whether that certificate should be trusted (chains to
a UCM-issued cert, not expired, not revoked); the caller
(``wstep_service.renew``) is responsible for that. Unlike EST's mTLS
renewal, where TLS already validated the presented cert's trust chain
before the app layer ever saw it, nothing here has validated trust yet —
signature verification alone only proves possession of a private key,
not that the matching certificate is one UCM should honor.
"""
import base64

import xmlsec

from .soap_envelope import DS_NS, WSSE_NS, WSU_NS


class WSSecurityError(Exception):
    """Raised when the signature is missing, malformed, or does not verify."""


def verify_signed_request(security_header):
    """Verify a ``wsse:Security`` header's ``ds:Signature``.

    Args:
        security_header: the lxml element for ``wsse:Security`` (as
            returned by ``rst_parser.ParsedRST.security_header``). Must
            not be ``None``.

    Returns:
        bytes: the DER-encoded signing certificate, once the signature is
        confirmed valid.

    Raises:
        WSSecurityError: on any missing element or verification failure.
    """
    if security_header is None:
        raise WSSecurityError('Request is not signed (no wsse:Security header)')

    bst_el = security_header.find(f'{{{WSSE_NS}}}BinarySecurityToken')
    if bst_el is None or not (bst_el.text or '').strip():
        raise WSSecurityError('wsse:Security is missing the signing BinarySecurityToken')

    try:
        cert_der = base64.b64decode(''.join(bst_el.text.split()), validate=True)
    except Exception as e:
        raise WSSecurityError(f'Invalid base64 in signing BinarySecurityToken: {e}')

    signature_node = security_header.find(f'{{{DS_NS}}}Signature')
    if signature_node is None:
        raise WSSecurityError('wsse:Security is missing ds:Signature')

    try:
        key = xmlsec.Key.from_memory(cert_der, xmlsec.constants.KeyDataFormatCertDer)
    except Exception as e:
        raise WSSecurityError(f'Could not load signing certificate: {e}')

    ctx = xmlsec.SignatureContext()
    ctx.key = key

    # A Reference with a non-empty "#<id>" URI targets a specific
    # wsu:Id-tagged element rather than the whole document (the
    # URI="" case xmlsec resolves natively against the containing
    # document); register any such ids so xmlsec can find the target.
    # Avoids interpolating attacker-controlled text into an XPath/
    # ElementPath expression — walks the tree and compares attribute
    # values directly instead.
    root = security_header.getroottree().getroot()
    for reference in signature_node.findall(f'{{{DS_NS}}}SignedInfo/{{{DS_NS}}}Reference'):
        uri = reference.get('URI') or ''
        if not uri.startswith('#'):
            continue
        target_id = uri[1:]
        for el in root.iter():
            if el.get(f'{{{WSU_NS}}}Id') == target_id:
                ctx.register_id(el, id_attr='Id', id_ns=WSU_NS)
                break

    try:
        ctx.verify(signature_node)
    except xmlsec.VerificationError as e:
        raise WSSecurityError(f'Signature verification failed: {e}')
    except xmlsec.Error as e:
        raise WSSecurityError(f'Signature processing error: {e}')

    return cert_der
