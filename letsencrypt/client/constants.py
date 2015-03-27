"""Let's Encrypt constants."""
import pkg_resources

from letsencrypt.acme import challenges


S_SIZE = 32
"""Size (in bytes) of secret base64-encoded octet string "s" used in
challenges."""

NONCE_SIZE = 16
"""Size of nonce used in JWS objects (in bytes)."""


EXCLUSIVE_CHALLENGES = frozenset([frozenset([
    challenges.DVSNI, challenges.SimpleHTTPS])])
"""Mutually exclusive challenges."""


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
    "letsencrypt.client.apache", "options-ssl.conf")
"""Path to the Apache mod_ssl config file found in the Let's Encrypt
distribution."""

APACHE_REWRITE_HTTPS_ARGS = [
    "^.*$", "https://%{SERVER_NAME}%{REQUEST_URI}", "[L,R=permanent]"]
"""Apache rewrite rule arguments used for redirections to https vhost"""


DVSNI_CHALLENGE_PORT = 443
"""Port to perform DVSNI challenge."""

CONFIG_DIR = "/etc/letsencrypt"
"""Location of the lets enecrypt config dir"""

WORK_DIR = "/var/lib/letsencrypt"
"""location of the data directory for lets encrypt"""

BACKUP_DIR = "backups"
"""Backups of config files"""

KEY_DIR = "keys"
"""Private key storage"""

CERT_DIR = "certs"
"""Certificate Storage"""

CERT_NAME = "cert-letsencrypt.pem"
"""Default name for certificate pemfile"""

CHAIN_NAME = "chain-letsencrypt.pem"
"""Default name for cert chain pemfile"""

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

NETSTAT = "/bin/netstat"
"""Location of netstat binary for checking whether a listener is already
running on the specified port (Linux-specific)."""


APACHE_SERVER_ROOT = "/etc/apache2"
APACHE_MOD_SSL_CONF = "/etc/letsencrypt/options-ssl.conf"
APACHE_CTL = "apache2ctl"
APACHE_ENMOD = "a2enmod"
APACHE_INIT_SCRIPT = "/etc/init.d/apache2"
LE_VHOST_EXT = "-le-ssl.conf"
ROLLBACK = 0
