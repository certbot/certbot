"""Apache plugin constants."""
import pkg_resources


CLI_DEFAULTS = dict(
    server_root="/etc/apache2",
    mod_ssl_conf="/etc/letsencrypt/options-ssl-apache.conf",
    ctl="apache2ctl",
    enmod="a2enmod",
    init_script="/etc/init.d/apache2",
)
"""CLI defaults."""


MOD_SSL_CONF = pkg_resources.resource_filename(
    "letsencrypt_apache", "options-ssl-apache.conf")
"""Path to the Apache mod_ssl config file found in the Let's Encrypt
distribution."""

REWRITE_HTTPS_ARGS = [
    "^.*$", "https://%{SERVER_NAME}%{REQUEST_URI}", "[L,R=permanent]"]
"""Apache rewrite rule arguments used for redirections to https vhost"""
