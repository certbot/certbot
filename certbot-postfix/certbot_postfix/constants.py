"""Postfix plugin constants."""

MINIMUM_VERSION = (2, 11,)

# If the value of a default VAR is a tuple, then the values which
# come LATER in the tuple are more strict/more secure.
# Certbot will default to the first value in the tuple, but will
# not override "more secure" settings.

ACCEPTABLE_SERVER_SECURITY_LEVELS = ("may", "encrypt")
ACCEPTABLE_CLIENT_SECURITY_LEVELS = ("may", "encrypt",
                                     "dane", "dane-only",
                                     "fingerprint",
                                     "verify", "secure")
ACCEPTABLE_CIPHER_LEVELS = ("medium", "high")

# Exporting certain ciphers to prevent logjam: https://weakdh.org/sysadmin.html
EXCLUDE_CIPHERS = ("aNULL, eNULL, EXPORT, DES, RC4, MD5, PSK, aECDH, "
                   "EDH-DSS-DES-CBC3-SHA, EDH-RSA-DES-CBC3-SHA, KRB5-DES, CBC3-SHA")


TLS_VERSIONS = ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2")
# Should NOT use SSLv2/3.
ACCEPTABLE_TLS_VERSIONS = ("TLSv1", "TLSv1.1", "TLSv1.2")

# Variables associated with enabling opportunistic TLS.
TLS_SERVER_VARS = {
    "smtpd_tls_security_level": ACCEPTABLE_SERVER_SECURITY_LEVELS,
}
TLS_CLIENT_VARS = {
    "smtp_tls_security_level": ACCEPTABLE_CLIENT_SECURITY_LEVELS,
}
# Default variables for a secure MTA server [receiver].
DEFAULT_SERVER_VARS = {
    "smtpd_tls_auth_only": "yes",
    "smtpd_tls_mandatory_protocols": "!SSLv2, !SSLv3",
    "smtpd_tls_protocols": "!SSLv2, !SSLv3",
    "smtpd_tls_ciphers": ACCEPTABLE_CIPHER_LEVELS,
    "smtpd_tls_mandatory_ciphers": ACCEPTABLE_CIPHER_LEVELS,
    "smtpd_tls_exclude_ciphers": EXCLUDE_CIPHERS,
    "smtpd_tls_eecdh_grade": "strong",
}

# Default variables for a secure MTA client [sender].
DEFAULT_CLIENT_VARS = {
    "smtp_tls_ciphers": ACCEPTABLE_CIPHER_LEVELS,
    "smtp_tls_exclude_ciphers": EXCLUDE_CIPHERS,
    "smtp_tls_mandatory_ciphers": ACCEPTABLE_CIPHER_LEVELS,
}

CLI_DEFAULTS = dict(
    config_dir="/etc/postfix",
    ctl="postfix",
    config_utility="postconf",
    tls_only=False,
    ignore_master_overrides=False,
    server_only=False,
)
"""CLI defaults."""
