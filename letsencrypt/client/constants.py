"""Let's Encrypt constants."""
import logging

from acme import challenges


SETUPTOOLS_PLUGINS_ENTRY_POINT = "letsencrypt.plugins"
"""Setuptools entry point group name for plugins."""


CLI_DEFAULTS = dict(
    config_files=["/etc/letsencrypt/cli.ini"],
    verbose_count=-(logging.WARNING / 10),
    server="www.letsencrypt-demo.org/acme/new-reg",
    rsa_key_size=2048,
    rollback_checkpoints=0,
    config_dir="/etc/letsencrypt",
    work_dir="/var/lib/letsencrypt",
    backup_dir="/var/lib/letsencrypt/backups",
    key_dir="/etc/letsencrypt/keys",
    certs_dir="/etc/letsencrypt/certs",
    cert_path="/etc/letsencrypt/certs/cert-letsencrypt.pem",
    chain_path="/etc/letsencrypt/certs/chain-letsencrypt.pem",
)
"""Defaults for CLI flags and `.IConfig` attributes."""


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


CONFIG_DIRS_MODE = 0o755
"""Directory mode for ``.IConfig.config_dir`` et al."""

TEMP_CHECKPOINT_DIR = "temp_checkpoint"
"""Temporary checkpoint directory (relative to IConfig.work_dir)."""

IN_PROGRESS_DIR = "IN_PROGRESS"
"""Directory used before a permanent checkpoint is finalized (relative to
IConfig.work_dir)."""

CERT_KEY_BACKUP_DIR = "keys-certs"
"""Directory where all certificates and keys are stored (relative to
IConfig.work_dir. Used for easy revocation."""

ACCOUNTS_DIR = "accounts"
"""Directory where all accounts are saved."""

ACCOUNT_KEYS_DIR = "keys"
"""Directory where account keys are saved. Relative to ACCOUNTS_DIR."""

REC_TOKEN_DIR = "recovery_tokens"
"""Directory where all recovery tokens are saved (relative to
IConfig.work_dir)."""

NETSTAT = "/bin/netstat"
"""Location of netstat binary for checking whether a listener is already
running on the specified port (Linux-specific)."""
