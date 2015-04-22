"""Apache plugin constants."""
import pkg_resources


# CLI/IConfig defaults
DEFAULT_SERVER_ROOT = "/etc/apache2"
DEFAULT_MOD_SSL_CONF = "/etc/letsencrypt/options-ssl.conf"
DEFAULT_CTL = "apache2ctl"
DEFAULT_ENMOD = "a2enmod"
DEFAULT_INIT_SCRIPT = "/etc/init.d/apache2"


MOD_SSL_CONF = pkg_resources.resource_filename(
    "letsencrypt.client.plugins.apache", "options-ssl.conf")
"""Path to the Apache mod_ssl config file found in the Let's Encrypt
distribution."""

REWRITE_HTTPS_ARGS = [
    "^.*$", "https://%{SERVER_NAME}%{REQUEST_URI}", "[L,R=permanent]"]
"""Apache rewrite rule arguments used for redirections to https vhost"""
