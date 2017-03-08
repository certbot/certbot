"""Certbot constants."""
import os
import logging

from acme import challenges


SETUPTOOLS_PLUGINS_ENTRY_POINT = "certbot.plugins"
"""Setuptools entry point group name for plugins."""

OLD_SETUPTOOLS_PLUGINS_ENTRY_POINT = "letsencrypt.plugins"
"""Plugins Setuptools entry point before rename."""

CLI_DEFAULTS = dict(
    config_files=[
        "/etc/letsencrypt/cli.ini",
        # http://freedesktop.org/wiki/Software/xdg-user-dirs/
        os.path.join(os.environ.get("XDG_CONFIG_HOME", "~/.config"),
                     "letsencrypt", "cli.ini"),
    ],
    verbose_count=-int(logging.INFO / 10),
    server="https://acme-v01.api.letsencrypt.org/directory",
    rsa_key_size=2048,
    rollback_checkpoints=1,
    config_dir="/etc/letsencrypt",
    work_dir="/var/lib/letsencrypt",
    logs_dir="/var/log/letsencrypt",
    no_verify_ssl=False,
    http01_port=challenges.HTTP01Response.PORT,
    tls_sni_01_port=challenges.TLSSNI01Response.PORT,

    auth_cert_path="./cert.pem",
    auth_chain_path="./chain.pem",
    strict_permissions=False,
)
STAGING_URI = "https://acme-staging.api.letsencrypt.org/directory"

# The set of reasons for revoking a certificate is defined in RFC 5280 in
# section 5.3.1. The reasons that users are allowed to submit are restricted to
# those accepted by the ACME server implementation. They are listed in
# `letsencrypt.boulder.revocation.reasons.go`.
REVOCATION_REASONS = {
    "unspecified": 0,
    "keycompromise": 1,
    "affiliationchanged": 3,
    "superseded": 4,
    "cessationofoperation": 5}

"""Defaults for CLI flags and `.IConfig` attributes."""

QUIET_LOGGING_LEVEL = logging.WARNING
"""Logging level to use in quiet mode."""

RENEWER_DEFAULTS = dict(
    renewer_enabled="yes",
    renew_before_expiry="30 days",
    # This value should ensure that there is never a deployment delay by
    # default.
    deploy_before_expiry="99 years",
)
"""Defaults for renewer script."""


ENHANCEMENTS = ["redirect", "http-header", "ocsp-stapling", "spdy"]
"""List of possible :class:`certbot.interfaces.IInstaller`
enhancements.

List of expected options parameters:
- redirect: None
- http-header: TODO
- ocsp-stapling: certificate chain file path
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

FORCE_INTERACTIVE_FLAG = "--force-interactive"
"""Flag to disable TTY checking in IDisplay."""

EFF_SUBSCRIBE_URI = "https://supporters.eff.org/subscribe/certbot"
"""EFF URI used to submit the e-mail address of users who opt-in."""
