""" Distribution specific override class for Gentoo Linux """
import zope.interface

from certbot import interfaces
from certbot_apache._internal import apache_util
from certbot_apache._internal import configurator
from certbot_apache._internal import parser


@zope.interface.provider(interfaces.IPluginFactory)
class GentooConfigurator(configurator.ApacheConfigurator):
    """Gentoo specific ApacheConfigurator override class"""

    OS_DEFAULTS = dict(
        server_root="/etc/apache2",
        vhost_root="/etc/apache2/vhosts.d",
        vhost_files="*.conf",
        logs_root="/var/log/apache2",
        ctl="apache2ctl",
        version_cmd=['apache2ctl', '-v'],
        restart_cmd=['apache2ctl', 'graceful'],
        restart_cmd_alt=['apache2ctl', 'restart'],
        conftest_cmd=['apache2ctl', 'configtest'],
        enmod=None,
        dismod=None,
        le_vhost_ext="-le-ssl.conf",
        handle_modules=False,
        handle_sites=False,
        challenge_location="/etc/apache2/vhosts.d",
        bin=None,
    )

    def _prepare_options(self):
        """
        Override the options dictionary initialization in order to support
        alternative restart cmd used in Gentoo.
        """
        super(GentooConfigurator, self)._prepare_options()
        self.options["restart_cmd_alt"][0] = self.option("ctl")

    def get_parser(self):
        """Initializes the ApacheParser"""
        return GentooParser(
            self.option("server_root"), self.option("vhost_root"),
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
        for k in defines:
            self.variables[k] = defines[k]

    def update_modules(self):
        """Get loaded modules from httpd process, and add them to DOM"""
        mod_cmd = [self.configurator.option("ctl"), "modules"]
        matches = apache_util.parse_from_subprocess(mod_cmd, r"(.*)_module")
        for mod in matches:
            self.add_mod(mod.strip())
