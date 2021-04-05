""" Distribution specific override class for Fedora 29+ """
from typing import cast
from typing import List

import zope.interface

from certbot import errors
from certbot import interfaces
from certbot import util
from certbot_apache._internal import apache_util
from certbot_apache._internal import configurator
from certbot_apache._internal import parser


@zope.interface.provider(interfaces.IPluginFactory)
class FedoraConfigurator(configurator.ApacheConfigurator):
    """Fedora 29+ specific ApacheConfigurator override class"""

    OS_DEFAULTS = dict(
        server_root="/etc/httpd",
        vhost_root="/etc/httpd/conf.d",
        vhost_files="*.conf",
        logs_root="/var/log/httpd",
        ctl="httpd",
        version_cmd=['httpd', '-v'],
        restart_cmd=['apachectl', 'graceful'],
        restart_cmd_alt=['apachectl', 'restart'],
        conftest_cmd=['apachectl', 'configtest'],
        enmod=None,
        dismod=None,
        le_vhost_ext="-le-ssl.conf",
        handle_modules=False,
        handle_sites=False,
        challenge_location="/etc/httpd/conf.d",
        bin=None,
    )

    def config_test(self):
        """
        Override config_test to mitigate configtest error in vanilla installation
        of mod_ssl in Fedora. The error is caused by non-existent self-signed
        certificates referenced by the configuration, that would be autogenerated
        during the first (re)start of httpd.
        """
        try:
            super().config_test()
        except errors.MisconfigurationError:
            self._try_restart_fedora()

    def get_parser(self):
        """Initializes the ApacheParser"""
        return FedoraParser(
            self.option("server_root"), self.option("vhost_root"),
            self.version, configurator=self)

    def _try_restart_fedora(self):
        """
        Tries to restart httpd using systemctl to generate the self signed keypair.
        """
        try:
            util.run_script(['systemctl', 'restart', 'httpd'])
        except errors.SubprocessError as err:
            raise errors.MisconfigurationError(str(err))

        # Finish with actual config check to see if systemctl restart helped
        super().config_test()

    def _prepare_options(self):
        """
        Override the options dictionary initialization to keep using apachectl
        instead of httpd and so take advantages of this new bash script in newer versions
        of Fedora to restart httpd.
        """
        super()._prepare_options()
        cast(List[str], self.options["restart_cmd"])[0] = 'apachectl'
        cast(List[str], self.options["restart_cmd_alt"])[0] = 'apachectl'
        cast(List[str], self.options["conftest_cmd"])[0] = 'apachectl'


class FedoraParser(parser.ApacheParser):
    """Fedora 29+ specific ApacheParser override class"""
    def __init__(self, *args, **kwargs):
        # Fedora 29+ specific configuration file for Apache
        self.sysconfig_filep = "/etc/sysconfig/httpd"
        super().__init__(*args, **kwargs)

    def update_runtime_variables(self):
        """ Override for update_runtime_variables for custom parsing """
        # Opportunistic, works if SELinux not enforced
        super().update_runtime_variables()
        self._parse_sysconfig_var()

    def _parse_sysconfig_var(self):
        """ Parses Apache CLI options from Fedora configuration file """
        defines = apache_util.parse_define_file(self.sysconfig_filep, "OPTIONS")
        for k in defines:
            self.variables[k] = defines[k]
