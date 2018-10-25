"""Sendmail Configuration"""
import sys
import logging
import os
import difflib
import re
import socket
import subprocess
import tempfile
import time

import OpenSSL
import six
import zope.component
import zope.interface

from certbot import constants as core_constants
from certbot import crypto_util
from certbot import errors
from certbot import interfaces
from certbot import util

from certbot.plugins import common

from certbot_sendmail import constants


logger = logging.getLogger(__name__)


class FileChanges(object):
    def __init__(self, filepath):
        self._filepath = filepath
        self._lines = []
        self._append = []
        if not os.path.isfile(filepath):
            open(filepath, "a").close()
        with open(filepath) as f:
            self._lines = f.readlines()
        self._diff = {} # line number: new line

    def replace_first(self, regex_find_line, replace_value, full_replace):
        """ regex to match line, new line to replace it with."""
        p = re.compile(regex_find_line)
        for i, line in enumerate(self._lines):
            result = re.search(p, line)
            if not result or not result.group("value"):
                continue
            start, end = result.span("value")
            self._diff[i] = line[0:start] + replace_value + line[end:]
            return
        self._append.append(full_replace)

    def flush(self, diff_file=None):
        """ print diff """
        new_filelines = []
        for i, line in enumerate(self._lines):
            to_append = line
            if i in self._diff:
                to_append = self._diff[i]
            new_filelines.append(to_append)
        new_filelines.extend(self._append)

        diff = "".join(difflib.unified_diff(self._lines, new_filelines))
        if diff_file:
            with open(diff_file, "w") as f:
                f.write(diff)
            message = ("The appropriate diff has been written to {diff_file}.\n"
                "Review these changes, then apply them with:\n\n"
                "    patch -b {tls_file} -i {diff_file}\n\n"
                "This should also create a backup of the original file at {tls_file}.orig\n").format(
                diff_file=diff_file, tls_file=self._filepath)
        else:
            message = ("Review and apply the following diff to {tls_file}."
                "Continue when finished:\n\n{content}\n\n".format(
                tls_file=self._filepath, content=diff))
        zope.component.getUtility(interfaces.IDisplay).notification(message, pause=True)

@zope.interface.implementer(interfaces.IInstaller)
@zope.interface.provider(interfaces.IPluginFactory)
class SendmailConfigurator(common.Installer):
    # pylint: disable=too-many-instance-attributes,too-many-public-methods
    """Sendmail configurator.

    .. todo:: Add proper support for comments in the config. Currently,
        config files modified by the configurator will lose all their comments.

    :ivar config: Configuration.
    :type config: :class:`~certbot.interfaces.IConfig`

    :ivar str save_notes: Human-readable config change notes

    :ivar reverter: saves and reverts checkpoints
    :type reverter: :class:`certbot.reverter.Reverter`

    """

    description = "Sendmail Web Server plugin - Alpha"

    @classmethod
    def add_parser_arguments(cls, add):
        add("server-root", default=constants.CLI_DEFAULTS["server_root"],
            help="Sendmail server root directory.")
        add("tls-config-file", default=constants.CLI_DEFAULTS["tls_config_file"],
            help="Filename for the relevant TLS options.")
        add("diff-file", default=constants.CLI_DEFAULTS["diff_file"],
            help="Optional output file for diff. If specified diff will be written"
            "to file rather than stdout.")

    @property
    def tls_config_file(self):
        """Sendmail TLS config file."""
        # TODO (sydli): check if there's an intermediate "TLS" directory; if so, drop
        # it there.
        return os.path.join(self.conf("server_root"), self.conf("tls-config-file"))

    def __init__(self, *args, **kwargs):
        """Initialize an Sendmail Configurator. """
        super(SendmailConfigurator, self).__init__(*args, **kwargs)

        # Files to save
        self.save_notes = ""
        self.reverter.recovery_routine()
        self.changes = None

    # This is called in determine_authenticator and determine_installer
    def prepare(self):
        """Prepare the authenticator/installer.

        :raises .errors.NoInstallationError: If Sendmail ctl cannot be found
        :raises .errors.MisconfigurationError: If Sendmail is misconfigured
        """
        # Prevent two Sendmail plugins from modifying a config at once
        try:
            util.lock_dir_until_exit(self.conf("server-root"))
        except (OSError, errors.LockError):
            logger.debug("Encountered error:", exc_info=True)
            raise errors.PluginError(
                "Unable to lock %s", self.conf("server-root"))
        self.changes = FileChanges(self.tls_config_file)

    # Entry point in main.py for installing cert
    def deploy_cert(self, domain, cert_path, key_path,
                    chain_path=None, fullchain_path=None):
        # pylint: disable=unused-argument
        """Deploys certificate to specified virtual host.
        """
        fullchain_dir, _ = os.path.split(fullchain_path)
        regex_metapattern = r"define\(`conf{param}',\s*`(?P<value>.+)'\)"
        full_string = "define(`conf{param}', `{value}')dnl\n"
        # TODO: Instead of setting CACERT_PATH to the live/ dir,
        # We should really just ensure that Let's Encrypt's cert
        # is trusted.
        config_params = {
            "CACERT_PATH": fullchain_dir,
            "CACERT": fullchain_path,
            "SERVER_CERT": cert_path,
            "SERVER_KEY": key_path,
            "CLIENT_CERT": cert_path,
            "CLIENT_KEY": key_path,
        }
        for param in config_params:
            yay_for_regex_parsing = regex_metapattern.format(param=param)
            self.changes.replace_first(yay_for_regex_parsing,
                config_params[param],
                full_string.format(param=param, value=config_params[param]))
        os.chmod(key_path, 0o644)

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
        raise NotImplemented("The Sendmail plugin does not support any enhancements")

    ######################################
    # Sendmail management (IInstaller)
    ######################################
    def restart(self):
        """Restarts sendmail. Not implemented. """
        try:
            proc = subprocess.Popen(["make", "-C", self.config("server_root")])
            out, err = proc.communicate()
            proc = subprocess.Popen(["service", "sendmail", "restart"])
            out, err = proc.communicate()
        except (OSError, ValueError):
            raise errors.MisconfigurationError("nginx restart failed")


    def config_test(self):  # pylint: disable=no-self-use
        """Check the configuration of Sendmail for errors.
        """
        pass

    def more_info(self):
        """Human-readable string to help understand the module"""
        return (
            "Configures Sendmail to install STARTTLS with a valid cert.{0}"
            "Server root: {root}{0}".format(
                os.linesep, root=self.parser.config_root))

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
        self.changes.flush(self.conf("diff_file"))

    def rollback_checkpoints(self, rollback=1):
        pass

    def recovery_routine(self):
        pass

    def get_all_names(self):
        """Returns all names that may be authenticated.
        """
        return []
