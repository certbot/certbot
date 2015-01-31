"""Config for Let's Encrypt."""
import os.path

import zope.component

from letsencrypt.client import interfaces


zope.component.moduleProvides(interfaces.IConfig)


ACME_SERVER = "letsencrypt-demo.org:443"
"""CA hostname (and optionally :port).

If you create your own server... change this line

Note: the server certificate must be trusted in order to avoid
further modifications to the client."""


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

KEY_DIR = os.path.join(CONFIG_DIR, "keys/")
"""Keys storage."""

CERT_DIR = os.path.join(CONFIG_DIR, "certs/")
"""Certificate storage."""


LE_VHOST_EXT = "-le-ssl.conf"
"""Let's Encrypt SSL vhost configuration extension."""

CERT_PATH = os.path.join(CERT_DIR, "cert-letsencrypt.pem")
"""Let's Encrypt cert file."""

CHAIN_PATH = os.path.join(CERT_DIR, "chain-letsencrypt.pem")
"""Let's Encrypt chain file."""


RSA_KEY_SIZE = 2048
"""Key size"""


APACHE_CTL = "/usr/sbin/apache2ctl"
"""Path to the ``apache2ctl`` binary, used for ``configtest`` and
retrieving Apache2 version number."""

APACHE_ENMOD = "apache"
"""Path to the Apache ``a2enmod`` binary."""

APACHE_INIT_SCRIPT = "/etc/init.d/apache2"
"""Path to the Apache init script (used for server reload/restart)."""

APACHE_REWRITE_HTTPS_ARGS = [
    "^.*$", "https://%{SERVER_NAME}%{REQUEST_URI}", "[L,R=permanent]"]
"""Apache rewrite rule arguments used for redirections to https vhost"""

APACHE_SERVER_ROOT = "/etc/apache2/"
"""Apache server root directory"""

APACHE_MOD_SSL_CONF = os.path.join(CONFIG_DIR, "options-ssl.conf")
"""Contains standard Apache SSL directives"""
