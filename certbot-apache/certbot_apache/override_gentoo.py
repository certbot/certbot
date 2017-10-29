""" Distribution specific override class for Gentoo Linux """

from certbot_apache import apache_util
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
        # Gentoo specific configuration file for Apache2
        self.apacheconfig_filep = "/etc/conf.d/apache2"
        super(GentooParser, self).__init__(*args, **kwargs)

    def update_runtime_variables(self):
        """ Override for update_runtime_variables for custom parsing """
        self.parse_sysconfig_var()

    def parse_sysconfig_var(self):
        """ Parses Apache CLI options from Gentoo configuration file """
        defines = apache_util.parse_define_file(self.apacheconfig_filep,
                                                "APACHE2_OPTS")
        for k in defines.keys():
            self.variables[k] = defines[k]
