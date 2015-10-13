"""Let's Encrypt constants."""
import os
import logging

from acme import challenges


SETUPTOOLS_PLUGINS_ENTRY_POINT = "letsencrypt.plugins"
"""Setuptools entry point group name for plugins."""

# http://standards.freedesktop.org/basedir-spec/latest/ar01s03.html
XDG_CONFIG_HOME = os.path.expanduser(
    os.environ.get("XDG_CONFIG_HOME", "~/.config"))
XDG_DATA_HOME = os.path.expanduser(
    os.environ.get("XDG_DATA_HOME", "~/.local/share"))

CLI_DEFAULTS = dict(
    config_files=[
        "/etc/letsencrypt/cli.ini",
        os.path.join(XDG_CONFIG_HOME, "letsencrypt", "cli.ini"),
    ],
    verbose_count=-(logging.WARNING / 10),
    server="https://acme-staging.api.letsencrypt.org/directory",
    rsa_key_size=2048,
    rollback_checkpoints=1,
    config_dir=os.path.join(XDG_CONFIG_HOME, "letsencrypt"),
    work_dir=os.path.join(XDG_DATA_HOME, "letsencrypt", "work"),
    logs_dir=os.path.join(XDG_DATA_HOME, "letsencrypt", "logs"),
    no_verify_ssl=False,
    dvsni_port=challenges.DVSNI.PORT,

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
    challenges.DVSNI, challenges.SimpleHTTP])])
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
