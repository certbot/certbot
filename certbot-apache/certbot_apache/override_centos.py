""" Distribution specific override class for CentOS family (RHEL, Fedora) """
from certbot_apache import configurator
from certbot_apache import parser

class CentOSConfigurator(configurator.OverrideConfigurator):
    """CentOS specific ApacheConfigurator override class"""
    def __init__(self, *args, **kwargs):
        super(CentOSConfigurator, self).__init__(*args, **kwargs)

    def get_parser(self):
        """Initializes the ApacheParser"""
        return CentOSParser(
            self.aug, self.conf("server-root"), self.conf("vhost-root"),
            self.version, configurator=self)


class CentOSParser(parser.ApacheParser):
    """CentOS specific ApacheParser override class"""
    def __init__(self, *args, **kwargs):
        super(CentOSParser, self).__init__(*args, **kwargs)

    def update_includes(self, *args, **kwargs):
        """ Override for update_includes for custom parsing """
        # Opportunistic, works if SELinux not enforced
        super(CentOSParser, self).update_includes(*args, **kwargs)
        # TODO: Parse /etc/sysconfig/apache
