"""nginx plugin constants."""
import pkg_resources


CLI_DEFAULTS = dict(
    server_root="/etc/nginx",
    mod_ssl_conf="/etc/letsencrypt/options-ssl-nginx.conf",
    ctl="nginx",
)
"""CLI defaults."""


MOD_SSL_CONF = pkg_resources.resource_filename(
    "letsencrypt.client.plugins.nginx", "options-ssl.conf")
"""Path to the Nginx mod_ssl config file found in the Let's Encrypt
distribution."""
