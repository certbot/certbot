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


TEMP_CHECKPOINT_DIR = "temp_checkpoint"
"""Temporary checkpoint directory (relative to IConfig.work_dir)."""

IN_PROGRESS_DIR = "IN_PROGRESS"
"""Directory used before a permanent checkpoint is finalized (relative to
IConfig.work_dir)."""

CERT_KEY_BACKUP_DIR = "keys-certs"
"""Directory where all certificates and keys are stored (relative to
IConfig.work_dir. Used for easy revocation."""

REC_TOKEN_DIR = "recovery_tokens"
"""Directory where all recovery tokens are saved (relative to
IConfig.work_dir)."""
