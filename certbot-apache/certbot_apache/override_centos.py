""" Distribution specific override class for CentOS family (RHEL, Fedora) """
from certbot import util

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
        self.sysconfig_filep = "/etc/sysconfig/httpd"
        super(CentOSParser, self).__init__(*args, **kwargs)

    def update_runtime_variables(self, *args, **kwargs):
        """ Override for update_runtime_variables for custom parsing """
        # Opportunistic, works if SELinux not enforced
        super(CentOSParser, self).update_runtime_variables(*args, **kwargs)
        self.parse_sysconfig_var()

    def parse_sysconfig_var(self):
        """ Parses Apache CLI options from CentOS configuration file """
        # Get list of words in the variable
        a_opts = util.get_var_from_file("OPTIONS",
                                        self.sysconfig_filep).split(" ")
        for i, v in enumerate(a_opts):
            # Handle Define statements and make sure it has an argument
            if v == "-D" and len(a_opts) >= i+2:
                # Add results to parser.variables dict
                var_parts = a_opts[i+1].partition("=")
                self.variables[var_parts[0]] = var_parts[2]

