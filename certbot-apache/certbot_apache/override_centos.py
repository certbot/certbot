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
        ctl="apachectl",
        version_cmd=['apachectl', '-v'],
        restart_cmd=['apachectl', 'graceful'],
        restart_cmd_alt=['apachectl', 'restart'],
        conftest_cmd=['apachectl', 'configtest'],
        enmod=None,
        dismod=None,
        le_vhost_ext="-le-ssl.conf",
        handle_modules=False,
        handle_sites=False,
        challenge_location="/etc/httpd/conf.d",
        MOD_SSL_CONF_SRC=pkg_resources.resource_filename(
            "certbot_apache", "centos-options-ssl-apache.conf")
    )

    def _prepare_options(self):
        """
        Override the options dictionary initialization in order to support
        alternative restart cmd used in CentOS.
        """
        super(CentOSConfigurator, self)._prepare_options()
        self.options["restart_cmd_alt"][0] = self.option("ctl")

    def get_parser(self):
        """Initializes the ApacheParser"""
        return CentOSParser(
            self.aug, self.option("server_root"), self.option("vhost_root"),
            self.version, configurator=self)

    def _deploy_cert(self, *args, **kwargs):
        """
        Override _deploy_cert in order to ensure that the Apache configuration
        has "LoadModule ssl_module..." before parsing the VirtualHost configuration
        that was created by Certbot
        """
        super(CentOSConfigurator, self)._deploy_cert(*args, **kwargs)
        if self.version < (2, 4, 0):
            self._deploy_loadmodule_ssl_if_needed()


    def _deploy_loadmodule_ssl_if_needed(self):
        """
        Add "LoadModule ssl_module <pre-existing path>" to main httpd.conf if
        it doesn't exist there already.
        """

        loadmods = self.parser.find_dir("LoadModule", "ssl_module", exclude=False)

        # We should have one in ssl.conf
        sslconf_loadmod_path = None
        loadmod_args = ["ssl_module", "modules/mod_ssl.so"]

        for m in loadmods:
            if "/conf.d/ssl.conf/" in m:
                # Strip "arg[1]" off from the end
                sslconf_loadmod_path = m[:-7]
                # Use the preconfigured LoadModule values from ssl.conf
                loadmod_args = self.parser.get_all_args(sslconf_loadmod_path)
            elif self.parser.loc["default"] in m:
                return

        rootconf_ifmod = self.parser._get_ifmod(  # pylint: disable=protected-access
            parser.get_aug_path(self.parser.loc["default"]),
            "!mod_ssl.c", beginning=True)
        # parser._get_ifmod returns a path postfixed with "/", remove that
        self.parser.add_dir(rootconf_ifmod[:-1], "LoadModule", loadmod_args)
        self.save_notes += "Added LoadModule ssl_module to main configuration.\n"

        # Wrap LoadModule mod_ssl inside of <IfModule !mod_ssl.c> if it's not
        # configured like this already.
        if sslconf_loadmod_path and "ifmodule" not in sslconf_loadmod_path.lower():
            sslconf_path = sslconf_loadmod_path.split("/directive")[0]
            # Remove the old LoadModule directive from ssl.conf
            self.aug.remove(sslconf_loadmod_path)

            # Create a new IfModule !mod_ssl.c
            ssl_ifmod = self.parser._get_ifmod(  # pylint: disable=protected-access
                sslconf_path, "!mod_ssl.c", beginning=True)

            self.parser.add_dir(ssl_ifmod[:-1], "LoadModule", loadmod_args)
            self.save_notes += ("Wrapped ssl.conf LoadModule ssl_module inside "
                                "of <IfModule !mod_ssl> block.\n")


class CentOSParser(parser.ApacheParser):
    """CentOS specific ApacheParser override class"""
    def __init__(self, *args, **kwargs):
        # CentOS specific configuration file for Apache
        self.sysconfig_filep = "/etc/sysconfig/httpd"
        super(CentOSParser, self).__init__(*args, **kwargs)

    def update_runtime_variables(self):
        """ Override for update_runtime_variables for custom parsing """
        # Opportunistic, works if SELinux not enforced
        super(CentOSParser, self).update_runtime_variables()
        self.parse_sysconfig_var()

    def parse_sysconfig_var(self):
        """ Parses Apache CLI options from CentOS configuration file """
        defines = apache_util.parse_define_file(self.sysconfig_filep, "OPTIONS")
        for k in defines.keys():
            self.variables[k] = defines[k]
