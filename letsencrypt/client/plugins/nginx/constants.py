"""nginx plugin constants."""
import pkg_resources


DEFAULT_SERVER_ROOT = "/etc/nginx"
DEFAULT_MOD_SSL_CONF = "/etc/letsencrypt/options-ssl-nginx.conf"
DEFAULT_CTL = "nginx"


MOD_SSL_CONF = pkg_resources.resource_filename(
    "letsencrypt.client.plugins.nginx", "options-ssl.conf")
"""Path to the Nginx mod_ssl config file found in the Let's Encrypt
distribution."""
