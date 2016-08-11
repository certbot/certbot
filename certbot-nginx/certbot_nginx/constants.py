"""nginx plugin constants."""
import pkg_resources


CLI_DEFAULTS = dict(
    server_root="/etc/nginx",
    ctl="nginx",
)
"""CLI defaults."""


MOD_SSL_CONF_DEST = "options-ssl-nginx.conf"
"""Name of the mod_ssl config file as saved in `IConfig.config_dir`."""

MOD_SSL_CONF_SRC = pkg_resources.resource_filename(
    "certbot_nginx", "options-ssl-nginx.conf")
"""Path to the nginx mod_ssl config file found in the Certbot
distribution."""

def os_constant(key):
    # XXX TODO: In the future, this could return different constants
    #           based on what OS we are running under.  To see an
    #           approach to how to handle different OSes, see the
    #           apache version of this file.  Currently, we do not
    #           actually have any OS-specific constants on Nginx.
    """
    Get a constant value for operating system

    :param key: name of cli constant
    :return: value of constant for active os
    """
    return CLI_DEFAULTS[key]
