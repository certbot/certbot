"""Apache plugin constants."""
import pkg_resources


CLI_DEFAULTS = dict(
    server_root="/etc/apache2",
    ctl="apache2ctl",
    enmod="a2enmod",
    dismod="a2dismod",
    init_script="/etc/init.d/apache2",
    le_vhost_ext="-le-ssl.conf",
)
"""CLI defaults."""

MOD_SSL_CONF_DEST = "options-ssl-apache.conf"
"""Name of the mod_ssl config file as saved in `IConfig.config_dir`."""

MOD_SSL_CONF_SRC = pkg_resources.resource_filename(
    "letsencrypt_apache", "options-ssl-apache.conf")
"""Path to the Apache mod_ssl config file found in the Let's Encrypt
distribution."""

REWRITE_HTTPS_ARGS = [
    "^", "https://%{SERVER_NAME}%{REQUEST_URI}", "[L,QSA,R=permanent]"]
"""Apache rewrite rule arguments used for redirections to https vhost"""
