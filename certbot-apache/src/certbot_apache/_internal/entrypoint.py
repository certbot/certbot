""" Entry point for Apache Plugin """

from certbot._internal.apache import entrypoint


ENTRYPOINT = entrypoint.get_configurator()
