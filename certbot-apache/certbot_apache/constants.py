"""Apache plugin constants."""
import pkg_resources


MOD_SSL_CONF_DEST = "options-ssl-apache.conf"
"""Name of the mod_ssl config file as saved in `IConfig.config_dir`."""


UPDATED_MOD_SSL_CONF_DIGEST = ".updated-options-ssl-apache-conf-digest.txt"
"""Name of the hash of the updated or informed mod_ssl_conf as saved in `IConfig.config_dir`."""

ALL_SSL_OPTIONS_HASHES = [
    '2086bca02db48daf93468332543c60ac6acdb6f0b58c7bfdf578a5d47092f82a',
    '4844d36c9a0f587172d9fa10f4f1c9518e3bcfa1947379f155e16a70a728c21a',
    '5a922826719981c0a234b1fbcd495f3213e49d2519e845ea0748ba513044b65b',
    '4066b90268c03c9ba0201068eaa39abbc02acf9558bb45a788b630eb85dadf27',
    'f175e2e7c673bd88d0aff8220735f385f916142c44aa83b09f1df88dd4767a88',
    'cfdd7c18d2025836ea3307399f509cfb1ebf2612c87dd600a65da2a8e2f2797b',
    '80720bd171ccdc2e6b917ded340defae66919e4624962396b992b7218a561791',
    'c0c022ea6b8a51ecc8f1003d0a04af6c3f2bc1c3ce506b3c2dfc1f11ef931082',
]
"""SHA256 hashes of the contents of previous versions of all versions of MOD_SSL_CONF_SRC"""

AUGEAS_LENS_DIR = pkg_resources.resource_filename(
    "certbot_apache", "augeas_lens")
"""Path to the Augeas lens directory"""

REWRITE_HTTPS_ARGS = [
    "^", "https://%{SERVER_NAME}%{REQUEST_URI}", "[L,NE,R=permanent]"]
"""Apache version<2.3.9 rewrite rule arguments used for redirections to
https vhost"""

REWRITE_HTTPS_ARGS_WITH_END = [
    "^", "https://%{SERVER_NAME}%{REQUEST_URI}", "[END,NE,R=permanent]"]
"""Apache version >= 2.3.9 rewrite rule arguments used for redirections to
    https vhost"""

OLD_REWRITE_HTTPS_ARGS = [
    ["^", "https://%{SERVER_NAME}%{REQUEST_URI}", "[L,QSA,R=permanent]"],
    ["^", "https://%{SERVER_NAME}%{REQUEST_URI}", "[END,QSA,R=permanent]"]]

HSTS_ARGS = ["always", "set", "Strict-Transport-Security",
             "\"max-age=31536000\""]
"""Apache header arguments for HSTS"""

UIR_ARGS = ["always", "set", "Content-Security-Policy",
            "upgrade-insecure-requests"]

HEADER_ARGS = {"Strict-Transport-Security": HSTS_ARGS,
               "Upgrade-Insecure-Requests": UIR_ARGS}

AUTOHSTS_STEPS = [60, 300, 900, 3600, 21600, 43200, 86400]
"""AutoHSTS increase steps: 1min, 5min, 15min, 1h, 6h, 12h, 24h"""

AUTOHSTS_PERMANENT = 31536000
"""Value for the last max-age of HSTS"""

AUTOHSTS_FREQ = 172800
"""Minimum time since last increase to perform a new one: 48h"""

MANAGED_COMMENT = "DO NOT REMOVE - Managed by Certbot"
MANAGED_COMMENT_ID = MANAGED_COMMENT+", VirtualHost id: {0}"
"""Managed by Certbot comments and the VirtualHost identification template"""
