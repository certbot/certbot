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
