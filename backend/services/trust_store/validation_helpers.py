"""
Name validation helpers for TrustStoreService
"""
import ipaddress
from cryptography import x509


def _name_value(name):
    """Extract string value from an x509.GeneralName."""
    if isinstance(name, x509.DNSName):
        return name.value
    elif isinstance(name, x509.RFC822Name):
        return name.value
    elif isinstance(name, x509.IPAddress):
        return str(name.value)
    return str(name)


def _name_matches_subtree(name, subtree):
    """Check if a GeneralName matches a NameConstraints subtree (RFC 5280 §4.2.1.10).

    DNS: "example.com" matches "example.com" and "sub.example.com"
    Email: "user@example.com" = that mailbox only; "example.com" = mailboxes on
        that host only; ".example.com" = mailboxes in the domain (not the host
        itself). This mirrors what OpenSSL enforces at chain validation.
    IP: network matching (e.g. 10.0.0.0/8 matches 10.1.2.3)
    """
    if type(name) != type(subtree):
        return False

    if isinstance(name, x509.DNSName):
        name_val = name.value.lower()
        constraint_val = subtree.value.lower()
        if name_val == constraint_val:
            return True
        if constraint_val.startswith('.'):
            return name_val.endswith(constraint_val) or name_val == constraint_val[1:]
        return name_val == constraint_val or name_val.endswith('.' + constraint_val)

    elif isinstance(name, x509.RFC822Name):
        name_val = name.value.lower()
        constraint_val = subtree.value.lower()
        # Domain is everything after the LAST '@' (a quoted local part may
        # contain one); cryptography already rejects bare multi-'@' addresses.
        name_domain = name_val.rpartition('@')[2] if '@' in name_val else name_val
        if '@' in constraint_val:
            # mailbox form: the exact address, nothing else
            return name_val == constraint_val
        if constraint_val.startswith('.'):
            # domain form: any host within the domain, but not the domain itself
            return name_domain.endswith(constraint_val)
        # host form: mail addressed to that specific host only
        return name_domain == constraint_val

    elif isinstance(name, x509.IPAddress):
        try:
            name_addr = name.value
            constraint_net = subtree.value
            if hasattr(constraint_net, 'network_address'):
                if hasattr(name_addr, 'network_address'):
                    return name_addr.subnet_of(constraint_net)
                return name_addr in constraint_net
            return name_addr == constraint_net
        except Exception:
            return False

    return False
