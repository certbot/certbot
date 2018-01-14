""" Distribution specific override class for Gentoo Linux """
import pkg_resources

import zope.interface

from certbot import interfaces

from certbot_apache import apache_util
from certbot_apache import configurator
from certbot_apache import parser

@zope.interface.provider(interfaces.IPluginFactory)
class GentooConfigurator(configurator.ApacheConfigurator):
    """Gentoo specific ApacheConfigurator override class"""

    OS_DEFAULTS = dict(
        server_root="/etc/apache2",
        vhost_root="/etc/apache2/vhosts.d",
        vhost_files="*.conf",
        logs_root="/var/log/apache2",
        version_cmd=['/usr/sbin/apache2', '-v'],
        apache_cmd="apache2ctl",
        restart_cmd=['apache2ctl', 'graceful'],
        conftest_cmd=['apache2ctl', 'configtest'],
        enmod=None,
        dismod=None,
        le_vhost_ext="-le-ssl.conf",
        handle_mods=False,
        handle_sites=False,
        challenge_location="/etc/apache2/vhosts.d",
        MOD_SSL_CONF_SRC=pkg_resources.resource_filename(
            "certbot_apache", "options-ssl-apache.conf")
    )

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
        self.update_modules()

    def parse_sysconfig_var(self):
        """ Parses Apache CLI options from Gentoo configuration file """
        defines = apache_util.parse_define_file(self.apacheconfig_filep,
                                                "APACHE2_OPTS")
        for k in defines.keys():
            self.variables[k] = defines[k]

    def update_modules(self):
        """Get loaded modules from httpd process, and add them to DOM"""
        mod_cmd = [self.configurator.constant("apache_cmd"), "modules"]
        matches = self.parse_from_subprocess(mod_cmd, r"(.*)_module")
        for mod in matches:
            self.add_mod(mod.strip())
