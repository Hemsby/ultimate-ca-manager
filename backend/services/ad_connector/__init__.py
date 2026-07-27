"""Active Directory connector: lets UCM query AD directly, decoupled from
SSO's own (unrelated) LDAP provider config. See ``lookup.py`` for the actual
LDAP client and the Kerberos-principal-to-computer-object lookup.
"""
