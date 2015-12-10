"""Apache plugin constants."""
import pkg_resources
from letsencrypt import le_util


CLI_DEFAULTS_DEBIAN = dict(
    server_root="/etc/apache2",
    vhost_root="/etc/apache2/sites-available",
    ctl="apache2ctl",
    enmod="a2enmod",
    dismod="a2dismod",
    le_vhost_ext="-le-ssl.conf",
    handle_mods=True,
    handle_sites=True,
    challenge_location="/etc/apache2"
)
CLI_DEFAULTS_CENTOS = dict(
    server_root="/etc/httpd",
    vhost_root="/etc/httpd/conf.d",
    ctl="apachectl",
    enmod=None,
    dismod=None,
    le_vhost_ext="-le-ssl.conf",
    handle_mods=False,
    handle_sites=False,
    challenge_location="/etc/httpd/conf.d"
)
CLI_DEFAULTS = {
    "debian": CLI_DEFAULTS_DEBIAN,
    "ubuntu": CLI_DEFAULTS_DEBIAN,
    "centos": CLI_DEFAULTS_CENTOS,
    "centos linux": CLI_DEFAULTS_CENTOS,
    "fedora": CLI_DEFAULTS_CENTOS,
    "red hat enterprise linux server": CLI_DEFAULTS_CENTOS
}
"""CLI defaults."""

MOD_SSL_CONF_DEST = "options-ssl-apache.conf"
"""Name of the mod_ssl config file as saved in `IConfig.config_dir`."""

MOD_SSL_CONF_SRC = pkg_resources.resource_filename(
    "letsencrypt_apache", "options-ssl-apache.conf")
"""Path to the Apache mod_ssl config file found in the Let's Encrypt
distribution."""

AUGEAS_LENS_DIR = pkg_resources.resource_filename(
    "letsencrypt_apache", "augeas_lens")
"""Path to the Augeas lens directory"""

REWRITE_HTTPS_ARGS = [
    "^", "https://%{SERVER_NAME}%{REQUEST_URI}", "[L,QSA,R=permanent]"]
"""Apache rewrite rule arguments used for redirections to https vhost"""


HSTS_ARGS = ["always", "set", "Strict-Transport-Security",
    "\"max-age=31536000; includeSubDomains\""]
"""Apache header arguments for HSTS"""

UIR_ARGS = ["always", "set", "Content-Security-Policy",
    "upgrade-insecure-requests"]

HEADER_ARGS = {"Strict-Transport-Security": HSTS_ARGS,
        "Upgrade-Insecure-Requests": UIR_ARGS}


def os_constant(key):
    """Get a constant value for operating system
    :param key: name of cli constant
    :return: value of constant for active os
    """
    os_info = le_util.get_os_info()
    try:
        constants = CLI_DEFAULTS[os_info[0].lower()]
    except KeyError:
        constants = CLI_DEFAULTS["debian"]
    return constants[key]
