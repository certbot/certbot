"""Config for Let's Encrypt."""
import os.path


ACME_SERVER = "letsencrypt-demo.org:443"
"""CA hostname (and optionally :port).

If you create your own server... change this line

Note: the server certificate must be trusted in order to avoid
further modifications to the client."""

# Directories
SERVER_ROOT = "/etc/apache2/"
"""Apache server root directory"""

CONFIG_DIR = "/etc/letsencrypt/"
"""Configuration file directory for letsencrypt"""

WORK_DIR = "/var/lib/letsencrypt/"
"""Working directory for letsencrypt"""

BACKUP_DIR = os.path.join(WORK_DIR, "backups/")
"""Directory where configuration backups are stored"""

TEMP_CHECKPOINT_DIR = os.path.join(WORK_DIR, "temp_checkpoint/")
"""Directory where temp checkpoint is created"""

IN_PROGRESS_DIR = os.path.join(BACKUP_DIR, "IN_PROGRESS/")
"""Directory used before a permanent checkpoint is finalized"""

CERT_KEY_BACKUP = os.path.join(WORK_DIR, "keys-certs/")
"""Directory where all certificates/keys are stored. Used for easy revocation"""

REV_TOKENS_DIR = os.path.join(WORK_DIR, "revocation_tokens/")
"""Directory where all revocation tokens are saved."""

KEY_DIR = os.path.join(SERVER_ROOT, "keys/")
"""Where all keys should be stored"""

CERT_DIR = os.path.join(SERVER_ROOT, "certs/")
"""Certificate storage"""

# Files and extensions
OPTIONS_SSL_CONF = os.path.join(CONFIG_DIR, "options-ssl.conf")
"""Contains standard Apache SSL directives"""

LE_VHOST_EXT = "-le-ssl.conf"
"""Let's Encrypt SSL vhost configuration extension"""

CERT_PATH = CERT_DIR + "cert-letsencrypt.pem"
"""Let's Encrypt cert file."""

CHAIN_PATH = CERT_DIR + "chain-letsencrypt.pem"
"""Let's Encrypt chain file."""

INVALID_EXT = ".acme.invalid"
"""Invalid Extension"""

# Challenge Sets
EXCLUSIVE_CHALLENGES = [frozenset(["dvsni", "simpleHttps"])]
"""Mutually Exclusive Challenges - only solve 1"""

DV_CHALLENGES = frozenset(["dvsni", "simpleHttps", "dns"])
"""These are challenges that must be solved by an Authenticator object"""

CLIENT_CHALLENGES = frozenset(
    ["recoveryToken", "recoveryContact", "proofOfPossession"])
"""These are challenges that are handled by client.py"""

# Challenge Constants
S_SIZE = 32
"""Byte size of S"""

NONCE_SIZE = 16
"""byte size of Nonce"""

# Key Sizes
RSA_KEY_SIZE = 2048
"""Key size"""

# Enhancements
ENHANCEMENTS = ["redirect", "http-header", "ocsp-stapling", "spdy"]
"""List of possible IInstaller enhancements.

List of expected options parameters:
redirect, None
http-header, TODO
ocsp-stapling, TODO
spdy, TODO

"""
# Apache Enhancement Arguments
REWRITE_HTTPS_ARGS = [
    "^.*$", "https://%{SERVER_NAME}%{REQUEST_URI}", "[L,R=permanent]"]
"""Rewrite rule arguments used for redirections to https vhost"""

# Apache Interaction
APACHE_CTL = "/usr/sbin/apache2ctl"
"""Command used for configtest and version number."""

APACHE2 = "/etc/init.d/apache2"
"""Command used for reload and restart."""

# TODO: add dnsutils to required/suggested packages
NSUPDATE_CMD = "nsupdate -k le-nsupdate.key"  # see "man nsupdate"
