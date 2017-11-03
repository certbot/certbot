""" Distribution specific override class for CentOS family (RHEL, Fedora) """
from certbot_apache import apache_util
from certbot_apache import configurator
from certbot_apache import parser

class CentOSConfigurator(configurator.OverrideConfigurator):
    """CentOS specific ApacheConfigurator override class"""
    def get_parser(self):
        """Initializes the ApacheParser"""
        return CentOSParser(
            self.aug, self.conf("server-root"), self.conf("vhost-root"),
            self.version, configurator=self)


class CentOSParser(parser.ApacheParser):
    """CentOS specific ApacheParser override class"""
    def __init__(self, *args, **kwargs):
        # CentOS specific configuration file for Apache
        self.sysconfig_filep = "/etc/sysconfig/httpd"
        super(CentOSParser, self).__init__(*args, **kwargs)

    def update_runtime_variables(self, *args, **kwargs):
        """ Override for update_runtime_variables for custom parsing """
        # Opportunistic, works if SELinux not enforced
        super(CentOSParser, self).update_runtime_variables(*args, **kwargs)
        self.parse_sysconfig_var()

    def parse_sysconfig_var(self):
        """ Parses Apache CLI options from CentOS configuration file """
        defines = apache_util.parse_define_file(self.sysconfig_filep, "OPTIONS")
        for k in defines.keys():
            self.variables[k] = defines[k]
