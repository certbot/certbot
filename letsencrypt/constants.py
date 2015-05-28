"""Let's Encrypt constants."""
import logging
import os

from acme import challenges


SETUPTOOLS_PLUGINS_ENTRY_POINT = "letsencrypt.plugins"
"""Setuptools entry point group name for plugins."""


_CLI_DEFAULT_CONFIG_DIR = "/etc/letsencrypt"
_CLI_DEFAULT_WORK_DIR = "/var/lib/letsencrypt"
_CLI_DEFAULT_CERT_DIR = os.path.join(_CLI_DEFAULT_CONFIG_DIR, "certs")
CLI_DEFAULTS = dict(
    config_files=["/etc/letsencrypt/cli.ini"],
    verbose_count=-(logging.WARNING / 10),
    server="https://www.letsencrypt-demo.org/acme/new-reg",
    rsa_key_size=2048,
    rollback_checkpoints=0,
    config_dir=_CLI_DEFAULT_CONFIG_DIR,
    work_dir=_CLI_DEFAULT_CONFIG_DIR,
    backup_dir=os.path.join(_CLI_DEFAULT_WORK_DIR, "backups"),
    key_dir=os.path.join(_CLI_DEFAULT_CONFIG_DIR, "keys"),
    certs_dir=_CLI_DEFAULT_CERT_DIR,
    cert_path=os.path.join(_CLI_DEFAULT_CERT_DIR, "cert-letsencrypt.pem"),
    chain_path=os.path.join(_CLI_DEFAULT_CERT_DIR, "chain-letsencrypt.pem"),
    test_mode=False,
)
"""Defaults for CLI flags and `.IConfig` attributes."""


RENEWER_DEFAULTS = dict(
    renewer_config_file="/etc/letsencrypt/renewer.conf",
    renewal_configs_dir="/etc/letsencrypt/configs",
    archive_dir="/etc/letsencrypt/archive",
    live_dir="/etc/letsencrypt/live",
    renewer_enabled="yes",
    renew_before_expiry="30 days",
    deploy_before_expiry="20 days",
)
"""Defaults for renewer script."""


EXCLUSIVE_CHALLENGES = frozenset([frozenset([
    challenges.DVSNI, challenges.SimpleHTTPS])])
"""Mutually exclusive challenges."""


ENHANCEMENTS = ["redirect", "http-header", "ocsp-stapling", "spdy"]
"""List of possible :class:`letsencrypt.interfaces.IInstaller`
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

BOULDER_TEST_MODE_CHALLENGE_PORT = 5001
"""Port that Boulder will connect on for validations in test mode."""

