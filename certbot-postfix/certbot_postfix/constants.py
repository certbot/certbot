"""Postfix plugin constants."""

POLICY_FILENAME = "starttls_everywhere_policy"

CA_CERTS_PATH = "/etc/ssl/certs/"

MINIMUM_VERSION = (2, 11,)

# If the value of a default VAR is a tuple, then the values which
# come LATER in the tuple are more strict/more secure.
# Certbot will default to the first value in the tuple, but will
# not override "more secure" settings.

ACCEPTABLE_SECURITY_LEVELS = ("may", "encrypt")
ACCEPTABLE_CIPHER_LEVELS = ("medium", "high")

TLS_VERSIONS = ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2")
# Should NOT use SSLv2/3.
ACCEPTABLE_TLS_VERSIONS = ("TLSv1", "TLSv1.1", "TLSv1.2")

# Default variables for a secure MTA server [receiver].
DEFAULT_SERVER_VARS = {
    "smtpd_tls_mandatory_protocols": "!SSLv2, !SSLv3",
    "smtpd_tls_protocols": "!SSLv2, !SSLv3",
    "smtpd_tls_security_level": ACCEPTABLE_SECURITY_LEVELS,
    "smtpd_tls_ciphers": ACCEPTABLE_CIPHER_LEVELS,
    "smtpd_tls_eecdh_grade": "strong",
}

# Default variables for a secure MTA client [sender].
DEFAULT_CLIENT_VARS = {
    "smtp_tls_security_level": ACCEPTABLE_SECURITY_LEVELS,
    "smtp_tls_ciphers": ACCEPTABLE_CIPHER_LEVELS,
}

CLI_DEFAULTS = dict(
    config_dir="/etc/postfix",
    ctl="postfix",
    config_utility="postconf",
    policy_file=POLICY_FILENAME,
)
"""CLI defaults."""
