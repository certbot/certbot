""" Distribution specific override class for Gentoo Linux """
from certbot_apache import configurator
from certbot_apache import parser


class GentooConfigurator(configurator.OverrideConfigurator):
    """Gentoo specific ApacheConfigurator override class"""
    def __init__(self, *args, **kwargs):
        super(GentooConfigurator, self).__init__(*args, **kwargs)

    def get_parser(self):
        """Initializes the ApacheParser"""
        return GentooParser(
            self.aug, self.conf("server-root"), self.conf("vhost-root"),
            self.version, configurator=self)


class GentooParser(parser.ApacheParser):
    """Gentoo specific ApacheParser override class"""
    def __init__(self, *args, **kwargs):
        super(GentooParser, self).__init__(*args, **kwargs)

    def update_includes(self):
        """ Override for update_includes for custom parsing """
        # TODO: Parse /etc/conf.d/apache2 APACHE_OPTS for Defines
        pass
