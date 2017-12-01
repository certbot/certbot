""" Distribution specific override class for CentOS family (RHEL, Fedora) """
import pkg_resources

import zope.interface

from certbot import interfaces

from certbot_apache import apache_util
from certbot_apache import configurator
from certbot_apache import parser

@zope.interface.provider(interfaces.IPluginFactory)
class CentOSConfigurator(configurator.ApacheConfigurator):
    """CentOS specific ApacheConfigurator override class"""

    OS_DEFAULTS = dict(
        server_root="/etc/httpd",
        vhost_root="/etc/httpd/conf.d",
        vhost_files="*.conf",
        logs_root="/var/log/httpd",
        version_cmd=['apachectl', '-v'],
        apache_cmd="apachectl",
        restart_cmd=['apachectl', 'graceful'],
        conftest_cmd=['apachectl', 'configtest'],
        enmod=None,
        dismod=None,
        le_vhost_ext="-le-ssl.conf",
        handle_mods=False,
        handle_sites=False,
        challenge_location="/etc/httpd/conf.d",
        MOD_SSL_CONF_SRC=pkg_resources.resource_filename(
            "certbot_apache", "centos-options-ssl-apache.conf")
    )

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
