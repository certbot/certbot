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
CLI_DEFAULTS_ARCH = dict(
    server_root="/etc/httpd",
    vhost_root="/etc/httpd/conf",
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
    challenge_location="/etc/httpd/conf",
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
    "arch": CLI_DEFAULTS_ARCH,
}
"""CLI defaults."""

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
