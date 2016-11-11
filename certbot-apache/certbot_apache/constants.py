"""Apache plugin constants."""
import pkg_resources
from certbot import util

CLI_DEFAULTS_DEFAULT = dict(
    server_root="/etc/apache2",
    vhost_root="/etc/apache2/sites-available",
    vhost_files="*",
    logs_root="/var/log/apache2",
    version_cmd=['apache2ctl', '-v'],
    define_cmd=['apache2ctl', '-t', '-D', 'DUMP_RUN_CFG'],
    restart_cmd=['apache2ctl', 'graceful'],
    conftest_cmd=['apache2ctl', 'configtest'],
    enmod=None,
    dismod=None,
    le_vhost_ext="-le-ssl.conf",
    handle_mods=False,
    handle_sites=False,
    challenge_location="/etc/apache2",
    MOD_SSL_CONF_SRC=pkg_resources.resource_filename(
        "certbot_apache", "options-ssl-apache.conf")
)
CLI_DEFAULTS_DEBIAN = dict(
    server_root="/etc/apache2",
    vhost_root="/etc/apache2/sites-available",
    vhost_files="*",
    logs_root="/var/log/apache2",
    version_cmd=['apache2ctl', '-v'],
    define_cmd=['apache2ctl', '-t', '-D', 'DUMP_RUN_CFG'],
    restart_cmd=['apache2ctl', 'graceful'],
    conftest_cmd=['apache2ctl', 'configtest'],
    enmod="a2enmod",
    dismod="a2dismod",
    le_vhost_ext="-le-ssl.conf",
    handle_mods=True,
    handle_sites=True,
    challenge_location="/etc/apache2",
    MOD_SSL_CONF_SRC=pkg_resources.resource_filename(
        "certbot_apache", "options-ssl-apache.conf")
)
CLI_DEFAULTS_CENTOS = dict(
    server_root="/etc/httpd",
    vhost_root="/etc/httpd/conf.d",
    vhost_files="*.conf",
    logs_root="/var/log/httpd",
    version_cmd=['apachectl', '-v'],
    define_cmd=['apachectl', '-t', '-D', 'DUMP_RUN_CFG'],
    restart_cmd=['apachectl', 'graceful'],
    conftest_cmd=['apachectl', 'configtest'],
    enmod=None,
    dismod=None,
    le_vhost_ext="-le-ssl.conf",
    handle_mods=False,
    handle_sites=False,
    challenge_location="/etc/httpd/conf.d",
    MOD_SSL_CONF_SRC=pkg_resources.resource_filename(
        "certbot_apache", "centos-options-ssl-apache.conf")
)
CLI_DEFAULTS_GENTOO = dict(
    server_root="/etc/apache2",
    vhost_root="/etc/apache2/vhosts.d",
    vhost_files="*.conf",
    logs_root="/var/log/apache2",
    version_cmd=['/usr/sbin/apache2', '-v'],
    define_cmd=['apache2ctl', 'virtualhosts'],
    restart_cmd=['apache2ctl', 'graceful'],
    conftest_cmd=['apache2ctl', 'configtest'],
    enmod=None,
    dismod=None,
    le_vhost_ext="-le-ssl.conf",
    handle_mods=False,
    handle_sites=False,
    challenge_location="/etc/apache2/vhosts.d",
    MOD_SSL_CONF_SRC=pkg_resources.resource_filename(
        "certbot_apache", "options-ssl-apache.conf")
)
CLI_DEFAULTS_DARWIN = dict(
    server_root="/etc/apache2",
    vhost_root="/etc/apache2/other",
    vhost_files="*.conf",
    logs_root="/var/log/apache2",
    version_cmd=['/usr/sbin/httpd', '-v'],
    define_cmd=['/usr/sbin/httpd', '-t', '-D', 'DUMP_RUN_CFG'],
    restart_cmd=['apachectl', 'graceful'],
    conftest_cmd=['apachectl', 'configtest'],
    enmod=None,
    dismod=None,
    le_vhost_ext="-le-ssl.conf",
    handle_mods=False,
    handle_sites=False,
    challenge_location="/etc/apache2/other",
    MOD_SSL_CONF_SRC=pkg_resources.resource_filename(
        "certbot_apache", "options-ssl-apache.conf")
)
CLI_DEFAULTS_SUSE = dict(
    server_root="/etc/apache2",
    vhost_root="/etc/apache2/vhosts.d",
    vhost_files="*.conf",
    logs_root="/var/log/apache2",
    version_cmd=['apache2ctl', '-v'],
    define_cmd=['apache2ctl', '-t', '-D', 'DUMP_RUN_CFG'],
    restart_cmd=['apache2ctl', 'graceful'],
    conftest_cmd=['apache2ctl', 'configtest'],
    enmod="a2enmod",
    dismod="a2dismod",
    le_vhost_ext="-le-ssl.conf",
    handle_mods=False,
    handle_sites=False,
    challenge_location="/etc/apache2/vhosts.d",
    MOD_SSL_CONF_SRC=pkg_resources.resource_filename(
        "certbot_apache", "options-ssl-apache.conf")
)
CLI_DEFAULTS = {
    "default": CLI_DEFAULTS_DEFAULT,
    "debian": CLI_DEFAULTS_DEBIAN,
    "ubuntu": CLI_DEFAULTS_DEBIAN,
    "centos": CLI_DEFAULTS_CENTOS,
    "centos linux": CLI_DEFAULTS_CENTOS,
    "fedora": CLI_DEFAULTS_CENTOS,
    "red hat enterprise linux server": CLI_DEFAULTS_CENTOS,
    "rhel": CLI_DEFAULTS_CENTOS,
    "amazon": CLI_DEFAULTS_CENTOS,
    "gentoo": CLI_DEFAULTS_GENTOO,
    "gentoo base system": CLI_DEFAULTS_GENTOO,
    "darwin": CLI_DEFAULTS_DARWIN,
    "opensuse": CLI_DEFAULTS_SUSE,
    "suse": CLI_DEFAULTS_SUSE,
}
"""CLI defaults."""

MOD_SSL_CONF_DEST = "options-ssl-apache.conf"
"""Name of the mod_ssl config file as saved in `IConfig.config_dir`."""

AUGEAS_LENS_DIR = pkg_resources.resource_filename(
    "certbot_apache", "augeas_lens")
"""Path to the Augeas lens directory"""

REWRITE_HTTPS_ARGS = [
    "^", "https://%{SERVER_NAME}%{REQUEST_URI}", "[L,QSA,R=permanent]"]
"""Apache version<2.3.9 rewrite rule arguments used for redirections to
https vhost"""

REWRITE_HTTPS_ARGS_WITH_END = [
    "^", "https://%{SERVER_NAME}%{REQUEST_URI}", "[END,QSA,R=permanent]"]
"""Apache version >= 2.3.9 rewrite rule arguments used for redirections to
    https vhost"""

HSTS_ARGS = ["always", "set", "Strict-Transport-Security",
             "\"max-age=31536000\""]
"""Apache header arguments for HSTS"""

UIR_ARGS = ["always", "set", "Content-Security-Policy",
            "upgrade-insecure-requests"]

HEADER_ARGS = {"Strict-Transport-Security": HSTS_ARGS,
               "Upgrade-Insecure-Requests": UIR_ARGS}


def os_constant(key):
    """
    Get a constant value for operating system

    :param key: name of cli constant
    :return: value of constant for active os
    """

    os_info = util.get_os_info()
    try:
        constants = CLI_DEFAULTS[os_info[0].lower()]
    except KeyError:
        constants = os_like_constants()
        if not constants:
            constants = CLI_DEFAULTS["default"]
    return constants[key]


def os_like_constants():
    """
    Try to get constants for distribution with
    similar layout and configuration, indicated by
    /etc/os-release variable "LIKE"

    :returns: Constants dictionary
    :rtype: `dict`
    """

    os_like = util.get_systemd_os_like()
    if os_like:
        for os_name in os_like:
            if os_name in CLI_DEFAULTS.keys():
                return CLI_DEFAULTS[os_name]
    return {}
