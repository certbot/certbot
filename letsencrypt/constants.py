"""Let's Encrypt constants."""
import os
import logging

from acme import challenges


SETUPTOOLS_PLUGINS_ENTRY_POINT = "letsencrypt.plugins"
"""Setuptools entry point group name for plugins."""

CLI_DEFAULTS = dict(
    config_files=[
        "/etc/letsencrypt/cli.ini",
        # http://freedesktop.org/wiki/Software/xdg-user-dirs/
        os.path.join(os.environ.get("XDG_CONFIG_HOME", "~/.config"),
                     "letsencrypt", "cli.ini"),
    ],
    verbose_count=-(logging.WARNING / 10),
    server="https://acme-staging.api.letsencrypt.org/directory",
    rsa_key_size=2048,
    rollback_checkpoints=1,
    config_dir="/etc/letsencrypt",
    work_dir="/var/lib/letsencrypt",
    logs_dir="/var/log/letsencrypt",
    no_verify_ssl=False,
    tls_sni_01_port=challenges.TLSSNI01Response.PORT,

    auth_cert_path="./cert.pem",
    auth_chain_path="./chain.pem",
    strict_permissions=False,
)
"""Defaults for CLI flags and `.IConfig` attributes."""


RENEWER_DEFAULTS = dict(
    renewer_enabled="yes",
    renew_before_expiry="30 days",
    deploy_before_expiry="20 days",
)
"""Defaults for renewer script."""


EXCLUSIVE_CHALLENGES = frozenset([frozenset([
    challenges.TLSSNI01, challenges.HTTP01])])
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

ARCHIVE_DIR = "archive"
"""Archive directory, relative to `IConfig.config_dir`."""

CONFIG_DIRS_MODE = 0o755
"""Directory mode for ``.IConfig.config_dir`` et al."""

ACCOUNTS_DIR = "accounts"
"""Directory where all accounts are saved."""

BACKUP_DIR = "backups"
"""Directory (relative to `IConfig.work_dir`) where backups are kept."""

CSR_DIR = "csr"
"""See `.IConfig.csr_dir`."""

IN_PROGRESS_DIR = "IN_PROGRESS"
"""Directory used before a permanent checkpoint is finalized (relative to
`IConfig.work_dir`)."""

KEY_DIR = "keys"
"""Directory (relative to `IConfig.config_dir`) where keys are saved."""

LIVE_DIR = "live"
"""Live directory, relative to `IConfig.config_dir`."""

TEMP_CHECKPOINT_DIR = "temp_checkpoint"
"""Temporary checkpoint directory (relative to `IConfig.work_dir`)."""

RENEWAL_CONFIGS_DIR = "renewal"
"""Renewal configs directory, relative to `IConfig.config_dir`."""

RENEWER_CONFIG_FILENAME = "renewer.conf"
"""Renewer config file name (relative to `IConfig.config_dir`)."""
