"""Dovecot Configuration"""
import logging
import os
import re
import socket
import subprocess
import tempfile
import time

import OpenSSL
import six
import zope.interface

from certbot import constants as core_constants
from certbot import crypto_util
from certbot import errors
from certbot import interfaces
from certbot import util

from certbot.plugins import common

from certbot_dovecot import constants


logger = logging.getLogger(__name__)


@zope.interface.implementer(interfaces.IAuthenticator, interfaces.IInstaller)
@zope.interface.provider(interfaces.IPluginFactory)
class DovecotConfigurator(common.Installer):
    # pylint: disable=too-many-instance-attributes,too-many-public-methods
    """Dovecot configurator.

    .. todo:: Add proper support for comments in the config. Currently,
        config files modified by the configurator will lose all their comments.

    :ivar config: Configuration.
    :type config: :class:`~certbot.interfaces.IConfig`

    :ivar str save_notes: Human-readable config change notes

    :ivar reverter: saves and reverts checkpoints
    :type reverter: :class:`certbot.reverter.Reverter`

    :ivar tup version: version of Dovecot

    """

    description = "Dovecot Web Server plugin - Alpha"

    @classmethod
    def add_parser_arguments(cls, add):
        add("server-root", default=constants.CLI_DEFAULTS["server_root"],
            help="Dovecot server root directory.")
        add("conf_cmd", default=constants.CLI_DEFAULTS["comf_cmd"], help="Path to the "
            "'doveconf' binary")
        add("adm_cmd", default=constants.CLI_DEFAULTS["adm_cmd"], help="Path to the "
            "'doveadm' binary")
        add("ctl", default=constants.CLI_DEFAULTS["ctl"], help="Path to the "
            "'dovecot' binary, used for 'configtest' and retrieving dovecot "
            "version number.")

    @property
    def dovecot_conf(self):
        """Dovecot SSL config file."""
        return os.path.join(self.conf("server_root"), "dovecot.conf")

    def __init__(self, *args, **kwargs):
        """Initialize an Dovecot Configurator.

        :param tup version: version of Dovecot as a tuple (1, 4, 7)
            (used mostly for unittesting)

        """
        version = kwargs.pop("version", None)
        super(DovecotConfigurator, self).__init__(*args, **kwargs)

        # Verify that all directories and files exist with proper permissions
        self._verify_setup()

        # Files to save
        self.save_notes = ""

        self.version = version
        self.reverter.recovery_routine()

    # This is called in determine_authenticator and determine_installer
    def prepare(self):
        """Prepare the authenticator/installer.

        :raises .errors.NoInstallationError: If Dovecot ctl cannot be found
        :raises .errors.MisconfigurationError: If Dovecot is misconfigured
        """
        # Verify Dovecot is installed
        if not util.exe_exists(self.conf('ctl')):
            raise errors.NoInstallationError

        # Make sure configuration is valid
        self.config_test()

        self.install_ssl_dhparams()

        # Set Version
        if self.version is None:
            self.version = self.get_version()

        # Prevent two Dovecot plugins from modifying a config at once
        try:
            util.lock_dir_until_exit(self.conf('server-root'))
        except (OSError, errors.LockError):
            logger.debug('Encountered error:', exc_info=True)
            raise errors.PluginError(
                'Unable to lock %s', self.conf('server-root'))

    # Entry point in main.py for installing cert
    def deploy_cert(self, domain, cert_path, key_path,
                    chain_path=None, fullchain_path=None):
        # pylint: disable=unused-argument
        """Deploys certificate to specified virtual host.

        .. note:: Aborts if the vhost is missing ssl_certificate or
            ssl_certificate_key.

        .. note:: This doesn't save the config files!

        :raises errors.PluginError: When unable to deploy certificate due to
            a lack of directives or configuration
        """
        directives_to_include = [
            "ssl = yes",
            "ssl_cert = <{}".format(fullchain_path),
            "ssl_key = <{}".format(key_path),
            # TODO (sydli): Use MOD_SSL_CONF like in nginx plugin
            "ssl_protocols = !SSLv3 !SSLv2",
            "ssl_prefer_server_ciphers = yes",
            "ssl_cipher_list = {}".format(constants.SSL_CIPHER_LIST),
            "ssl_dh_parameters_length = 2048",
        ]
        if self.version >= (2, 3, 0):
            directives_to_include.append("ssl_dh = <{}".format(self.ssl_dhparams))
        comment = " # Managed by Certbot"
        # TODO (sydli): make this operation idempotent...
        directives_to_include = ["{} {}\n".format(directive, comment) for directive in directives_to_include]
        with open(self.dovecot_conf, 'a') as ssl_conf:
            ssl_conf.writelines(directives_to_include)
        logger.info("Deployed Certificate to Dovecot")
        for directive in directives_to_include:
            self.save_notes += "\t{}\n".format(directive)

    ##################################
    # enhancement methods (IInstaller)
    ##################################
    def supported_enhancements(self):  # pylint: disable=no-self-use
        """Returns currently supported enhancements."""
        return []

    def enhance(self, domain, enhancement, options=None):
        """Enhance configuration.

        :param str domain: domain to enhance
        :param str enhancement: enhancement type defined in
            :const:`~certbot.constants.ENHANCEMENTS`
        :param options: options for the enhancement
            See :const:`~certbot.constants.ENHANCEMENTS`
            documentation for appropriate parameter.

        """
        raise NotImplemented("The Dovecot plugin does not support any enhancements")

    ######################################
    # Dovecot management (IInstaller)
    ######################################
    def restart(self):
        """Restarts dovecot.

        :raises .errors.MisconfigurationError: If either the reload fails.

        """
        dovecot_restart(self.conf('adm_cmd'), self.dovecot_conf)

    def config_test(self):  # pylint: disable=no-self-use
        """Check the configuration of Dovecot for errors.

        :raises .errors.MisconfigurationError: If config_test fails

        """
        try:
            util.run_script([self.conf('conf_cmd'), "-c", self.dovecot_conf])
        except errors.SubprocessError as err:
            raise errors.MisconfigurationError(str(err))

    def _verify_setup(self):
        """Verify the setup to ensure safe operating environment.

        Make sure that files/directories are setup with appropriate permissions
        Aim for defensive coding... make sure all input files
        have permissions of root.

        """
        uid = os.geteuid()
        util.make_or_verify_dir(
            self.config.work_dir, core_constants.CONFIG_DIRS_MODE, uid)
        util.make_or_verify_dir(
            self.config.backup_dir, core_constants.CONFIG_DIRS_MODE, uid)
        util.make_or_verify_dir(
            self.config.config_dir, core_constants.CONFIG_DIRS_MODE, uid)

    def get_version(self):
        """Return version of Dovecot Server.

        Version is returned as tuple. (ie. 2.4.7 = (2, 4, 7))

        :returns: version
        :rtype: tuple

        :raises .PluginError:
            Unable to find Dovecot version or version is unsupported

        """
        try:
            proc = subprocess.Popen(
                [self.conf('ctl'), "--version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True)
            text = proc.communicate()[1]
        except (OSError, ValueError) as error:
            logger.debug(error, exc_info=True)
            raise errors.PluginError(
                "Unable to run %s --version" % self.conf('ctl'))

        version_regex = re.compile(r"([0-9\.]*)", re.IGNORECASE)
        version_matches = version_regex.findall(text)

        if not version_matches:
            raise errors.PluginError("Unable to find Nginx version")

        version = tuple([int(i) for i in version_matches[0].split(".")])

        return version

    def more_info(self):
        """Human-readable string to help understand the module"""
        return (
            "Configures Dovecot to authenticate and install HTTPS.{0}"
            "Server root: {root}{0}"
            "Version: {version}".format(
                os.linesep, root=self.parser.config_root,
                version=".".join(str(i) for i in self.version))
        )

    ###################################################
    # Wrapper functions for Reverter class (IInstaller)
    ###################################################
    def save(self, title=None, temporary=False):
        """Saves all changes to the configuration files.

        :param str title: The title of the save. If a title is given, the
            configuration will be saved as a new checkpoint and put in a
            timestamped directory.

        :param bool temporary: Indicates whether the changes made will
            be quickly reversed in the future (ie. challenges)

        :raises .errors.PluginError: If there was an error in
            an attempt to save the configuration, or an error creating a
            checkpoint

        """
        return None
        # save_files = set(self.parser.parsed.keys())
        # self.add_to_checkpoint(save_files, self.save_notes, temporary)
        # self.save_notes = ""

        # # Change 'ext' to something else to not override existing conf files
        # self.parser.filedump(ext='')
        # if title and not temporary:
        #     self.finalize_checkpoint(title)

def dovecot_restart(dovecot_adm_ctl, dovecot_conf):
    """Restarts Dovecot.

    :param str dovecot_adm_ctl: Path to the doveadm binary.

    """
    try:
        proc = subprocess.Popen([dovecot_adm_ctl, "reload"])
        proc.communicate()
    except (OSError, ValueError):
        raise errors.MisconfigurationError("dovecot restart failed")
