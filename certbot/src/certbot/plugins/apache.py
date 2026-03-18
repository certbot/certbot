"""Despite being public API, this is only meant for use in our certbot-apache plugin, and isn't
intended for public use."""

from certbot._internal.plugins.apache import entrypoint


ENTRYPOINT = entrypoint.get_configurator()
