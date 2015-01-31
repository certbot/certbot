"""Let's Encrypt constants."""
import pkg_resources


S_SIZE = 32
"""Size (in bytes) of secret base64-encoded octet string "s" used in
challanges."""

NONCE_SIZE = 16
"""Size of nonce used in JWS objects (in bytes)."""


EXCLUSIVE_CHALLENGES = [frozenset(["dvsni", "simpleHttps"])]
"""Mutually exclusive challenges."""

DV_CHALLENGES = frozenset(["dvsni", "simpleHttps", "dns"])
"""Challenges that must be solved by a
:class:`letsencrypt.client.interfaces.IAuthenticator` object."""

CLIENT_CHALLENGES = frozenset(
    ["recoveryToken", "recoveryContact", "proofOfPossession"])
"""Challenges that are handled by the Let's Encrypt client."""


ENHANCEMENTS = ["redirect", "http-header", "ocsp-stapling", "spdy"]
"""List of possible :class:`letsencrypt.client.interfaces.IInstaller`
enhancements.

List of expected options parameters:
- redirect: None
- http-header: TODO
- ocsp-stapling: TODO
- spdy: TODO

"""


APACHE_MOD_SSL_CONF = pkg_resources.resource_filename(
    'letsencrypt.client.apache', 'options-ssl.conf')
"""Path to the Apache mod_ssl config file found in the Let's Encrypt
distribution."""

APACHE_REWRITE_HTTPS_ARGS = [
    "^.*$", "https://%{SERVER_NAME}%{REQUEST_URI}", "[L,R=permanent]"]
"""Apache rewrite rule arguments used for redirections to https vhost"""


DVSNI_DOMAIN_SUFFIX = ".acme.invalid"
"""Suffix appended to domains in DVSNI validation."""
