""" Distribution specific override class for Gentoo Linux """
from typing import Any

from certbot_apache._internal import apache_util
from certbot_apache._internal import configurator
from certbot_apache._internal import parser
from certbot_apache._internal.configurator import OsOptions


class GentooConfigurator(configurator.ApacheConfigurator):
    """Gentoo specific ApacheConfigurator override class"""

    OS_DEFAULTS = OsOptions(
        server_root="/etc/apache2",
        vhost_root="/etc/apache2/vhosts.d",
        vhost_files="*.conf",
        restart_cmd_alt=['apache2ctl', 'restart'],
        challenge_location="/etc/apache2/vhosts.d",
    )

    def _prepare_options(self) -> None:
        """
        Override the options dictionary initialization in order to support
        alternative restart cmd used in Gentoo.
        """
        super()._prepare_options()
        if not self.options.restart_cmd_alt:  # pragma: no cover
            raise ValueError("OS option restart_cmd_alt must be set for Gentoo.")
        self.options.restart_cmd_alt[0] = self.options.ctl

    def get_parser(self) -> "GentooParser":
        """Initializes the ApacheParser"""
        return GentooParser(
            self.options.server_root, self.options.vhost_root,
            self.version, configurator=self)


class GentooParser(parser.ApacheParser):
    """Gentoo specific ApacheParser override class"""
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        # Gentoo specific configuration file for Apache2
        self.apacheconfig_filep = "/etc/conf.d/apache2"
        super().__init__(*args, **kwargs)

    def update_runtime_variables(self) -> None:
        """ Override for update_runtime_variables for custom parsing """
        self.parse_sysconfig_var()
        self.update_modules()

    def parse_sysconfig_var(self) -> None:
        """ Parses Apache CLI options from Gentoo configuration file """
        defines = apache_util.parse_define_file(self.apacheconfig_filep,
                                                "APACHE2_OPTS")
        for k, v in defines.items():
            self.variables[k] = v

    def update_modules(self) -> None:
        """Get loaded modules from httpd process, and add them to DOM"""
        mod_cmd = [self.configurator.options.ctl, "modules"]
        matches = apache_util.parse_from_subprocess(mod_cmd, r"(.*)_module")
        for mod in matches:
            self.add_mod(mod.strip())
