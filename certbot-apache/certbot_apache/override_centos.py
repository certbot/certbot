""" Distribution specific override class for CentOS family (RHEL, Fedora) """
import logging
import pkg_resources

from acme.magic_typing import List  # pylint: disable=unused-import, no-name-in-module

import zope.interface

from certbot import interfaces

from certbot_apache import apache_util
from certbot_apache import configurator
from certbot_apache import parser

logger = logging.getLogger(__name__)


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

        # We should have at least one LoadModule ssl_module in the config
        loadmod_args = []  # type: List[str]
        loadmod_path = None
        for m in loadmods:
            noarg_path = m.rpartition("/")[0]
            path_args = self.parser.get_all_args(noarg_path)
            if loadmod_args:
                if loadmod_args != path_args:
                    logger.info("Multiple different LoadModule directives for mod_ssl "
                                "were found. If you encounter issues with resulting "
                                "configuration, it's suggested to move the LoadModule "
                                "ssl_module directive to the beginning of main httpd.conf.")
                    return
            else:
                loadmod_args = path_args
                loadmod_path = noarg_path
            if self.parser.loc["default"] in noarg_path:
                # LoadModule already in the main configuration file, NOOP
                return

        if not loadmod_args:
            # Do not try to enable mod_ssl
            return

        rootconf_ifmod = self.parser.get_ifmod(
            parser.get_aug_path(self.parser.loc["default"]),
            "!mod_ssl.c", beginning=True)
        # parser.get_ifmod returns a path postfixed with "/", remove that
        self.parser.add_dir(rootconf_ifmod[:-1], "LoadModule", loadmod_args)
        self.save_notes += "Added LoadModule ssl_module to main configuration.\n"

        # Wrap LoadModule mod_ssl inside of <IfModule !mod_ssl.c> if it's not
        # configured like this already.
        if loadmod_path and "ifmodule" not in loadmod_path.lower():
            sslconf_path = loadmod_path.split("/directive")[0]
            # Remove the old LoadModule directive
            self.aug.remove(loadmod_path)

            # Create a new IfModule !mod_ssl.c
            ssl_ifmod = self.parser.get_ifmod(sslconf_path, "!mod_ssl.c", beginning=True)

            self.parser.add_dir(ssl_ifmod[:-1], "LoadModule", loadmod_args)
            self.save_notes += ("Wrapped pre-existing LoadModule ssl_module "
                                "inside of <IfModule !mod_ssl> block.\n")


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
