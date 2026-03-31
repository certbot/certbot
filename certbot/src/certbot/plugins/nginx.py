"""Despite being public API, this is only meant for use in our certbot-nginx plugin, and isn't
intended for public use."""

from certbot._internal.plugins.nginx import configurator


ENTRYPOINT = configurator.NginxConfigurator
