""" Entry point for Apache Plugin """

from certbot._internal.plugins.nginx import configurator


ENTRYPOINT = configurator.NginxConfigurator
