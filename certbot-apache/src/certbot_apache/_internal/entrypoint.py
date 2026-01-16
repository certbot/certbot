""" Entry point for Apache Plugin """

from certbot._internal.plugins.apache import entrypoint


ENTRYPOINT = entrypoint.get_configurator()
