"""Tests for _is_valid_domain in api/v2/acme_local_domains.py

Covers the bare-TLD support (#290): a bare private TLD (e.g. "local") can be
registered so find_local_domain_ca's parent-walking covers its subdomains.
"""
import pytest

from api.v2.acme_local_domains import _is_valid_domain


@pytest.mark.parametrize("domain", [
    # Bare TLDs (#290)
    "local",
    "internal",
    "lab",
    "corp",
    "home",
    "ab",                     # two-letter bare TLD (minimum length)
    # Wildcard bare TLDs (#290)
    "*.local",
    "*.internal",
    # Standard domains
    "example.com",
    "foo.example.com",
    "bar.foo.example.com",
    # Wildcards
    "*.example.com",
    "*.foo.example.com",
    # Hyphens and digits in labels
    "my-domain.com",
    "a-b.example.com",
    "123.com",
    "s1.example.com",
])
def test_valid_domains(domain):
    assert _is_valid_domain(domain), f"{domain!r} should be accepted"


@pytest.mark.parametrize("domain", [
    # Empty / whitespace
    "",
    "   ",
    # Wildcard without TLD
    "*",
    "*.",
    # Leading/trailing dot
    ".com",
    "example.com.",
    "..com",
    # Double wildcard
    "**.example.com",
    "*.*.example.com",
    # Invalid characters
    "exa_mple.com",
    "exa mple.com",
    "example!.com",
    # TLD length/charset (2+ alpha chars required)
    "a",
    "example.123",
    # Hyphen at label boundary
    "-example.com",
    "example-.com",
    # Path traversal / injection
    "../etc/passwd",
    "..",
    "example.com\n",
    "ex\nample.com",
])
def test_invalid_domains(domain):
    assert not _is_valid_domain(domain), f"{domain!r} should be rejected"
