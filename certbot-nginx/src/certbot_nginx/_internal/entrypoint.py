""" Entry point for Apache Plugin """

from certbot._internal.nginx import configurator


ENTRYPOINT = configurator.NginxConfigurator
