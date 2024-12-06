"""Apache plugin constants."""
import atexit
import importlib.resources
from contextlib import ExitStack
from typing import Dict
from typing import List


MOD_SSL_CONF_DEST = "options-ssl-apache.conf"
"""Name of the mod_ssl config file as saved
in `certbot.configuration.NamespaceConfig.config_dir`."""


UPDATED_MOD_SSL_CONF_DIGEST = ".updated-options-ssl-apache-conf-digest.txt"
"""Name of the hash of the updated or informed mod_ssl_conf as saved
in `certbot.configuration.NamespaceConfig.config_dir`."""

# NEVER REMOVE A SINGLE HASH FROM THIS LIST UNLESS YOU KNOW EXACTLY WHAT YOU ARE DOING!
ALL_SSL_OPTIONS_HASHES: List[str] = [
    '2086bca02db48daf93468332543c60ac6acdb6f0b58c7bfdf578a5d47092f82a',
    '4844d36c9a0f587172d9fa10f4f1c9518e3bcfa1947379f155e16a70a728c21a',
    '5a922826719981c0a234b1fbcd495f3213e49d2519e845ea0748ba513044b65b',
    '4066b90268c03c9ba0201068eaa39abbc02acf9558bb45a788b630eb85dadf27',
    'f175e2e7c673bd88d0aff8220735f385f916142c44aa83b09f1df88dd4767a88',
    'cfdd7c18d2025836ea3307399f509cfb1ebf2612c87dd600a65da2a8e2f2797b',
    '80720bd171ccdc2e6b917ded340defae66919e4624962396b992b7218a561791',
    'c0c022ea6b8a51ecc8f1003d0a04af6c3f2bc1c3ce506b3c2dfc1f11ef931082',
    '717b0a89f5e4c39b09a42813ac6e747cfbdeb93439499e73f4f70a1fe1473f20',
    '0fcdc81280cd179a07ec4d29d3595068b9326b455c488de4b09f585d5dafc137',
    '86cc09ad5415cd6d5f09a947fe2501a9344328b1e8a8b458107ea903e80baa6c',
    '06675349e457eae856120cdebb564efe546f0b87399f2264baeb41e442c724c7',
    '5cc003edd93fb9cd03d40c7686495f8f058f485f75b5e764b789245a386e6daf',
    '007cd497a56a3bb8b6a2c1aeb4997789e7e38992f74e44cc5d13a625a738ac73',
    '34783b9e2210f5c4a23bced2dfd7ec289834716673354ed7c7abf69fe30192a3',
    '61466bc2f98a623c02be8a5ee916ead1655b0ce883bdc936692076ea499ff5ce',
    '3fd812e3e87fe5c645d3682a511b2a06c8286f19594f28e280f17cd6af1301b5',
]
"""SHA256 hashes of the contents of previous versions of all versions of MOD_SSL_CONF_SRC"""

def _generate_augeas_lens_dir_static() -> str:
    # This code ensures that the resource is accessible as file for the lifetime of current
    # Python process, and will be automatically cleaned up on exit.
    file_manager = ExitStack()
    atexit.register(file_manager.close)
    augeas_lens_dir_ref = importlib.resources.files("certbot_apache") / "_internal" / "augeas_lens"
    return str(file_manager.enter_context(importlib.resources.as_file(augeas_lens_dir_ref)))

AUGEAS_LENS_DIR = _generate_augeas_lens_dir_static()
"""Path to the Augeas lens directory"""

REWRITE_HTTPS_ARGS: List[str] = [
    "^", "https://%{SERVER_NAME}%{REQUEST_URI}", "[END,NE,R=permanent]"]
"""Apache version >= 2.3.9 rewrite rule arguments used for redirections to
    https vhost"""

OLD_REWRITE_HTTPS_ARGS: List[List[str]] = [
    ["^", "https://%{SERVER_NAME}%{REQUEST_URI}", "[L,QSA,R=permanent]"],
    ["^", "https://%{SERVER_NAME}%{REQUEST_URI}", "[END,QSA,R=permanent]"],
    ["^", "https://%{SERVER_NAME}%{REQUEST_URI}", "[L,NE,R=permanent]"]]

HSTS_ARGS: List[str] = ["always", "set", "Strict-Transport-Security",
             "\"max-age=31536000\""]
"""Apache header arguments for HSTS"""

UIR_ARGS: List[str] = ["always", "set", "Content-Security-Policy", "upgrade-insecure-requests"]

HEADER_ARGS: Dict[str, List[str]] = {
    "Strict-Transport-Security": HSTS_ARGS, "Upgrade-Insecure-Requests": UIR_ARGS,
}

AUTOHSTS_STEPS: List[int] = [60, 300, 900, 3600, 21600, 43200, 86400]
"""AutoHSTS increase steps: 1min, 5min, 15min, 1h, 6h, 12h, 24h"""

AUTOHSTS_PERMANENT: int = 31536000
"""Value for the last max-age of HSTS"""

AUTOHSTS_FREQ: int = 172800
"""Minimum time since last increase to perform a new one: 48h"""

MANAGED_COMMENT: str = "DO NOT REMOVE - Managed by Certbot"
MANAGED_COMMENT_ID: str = MANAGED_COMMENT + ", VirtualHost id: {0}"
"""Managed by Certbot comments and the VirtualHost identification template"""
