"""Certbot installer plugin for Postfix."""
import logging
import os
import subprocess

import zope.interface

from certbot import errors
from certbot import interfaces
from certbot import util as certbot_util
from certbot.plugins import common as plugins_common
from certbot.plugins import util as plugins_util

from certbot_postfix import util


logger = logging.getLogger(__name__)


@zope.interface.implementer(interfaces.IInstaller)
@zope.interface.provider(interfaces.IPluginFactory)
class Installer(plugins_common.Installer):
    """Certbot installer plugin for Postfix.

    :ivar str config_dir: Postfix configuration directory to modify
    :ivar dict proposed_changes: configuration parameters and values to
        be written to the Postfix config when save() is called
    :ivar list save_notes: documentation for proposed changes. This is
        cleared and stored in Certbot checkpoints when save() is called

    """

    description = "Configure TLS with the Postfix MTA"

    @classmethod
    def add_parser_arguments(cls, add):
        add("ctl", default="postfix",
            help="Path to the 'postfix' control program.")
        add("config-dir", help="Path to the directory containing the "
            "Postfix main.cf file to modify instead of using the "
            "default configuration paths.")
        add("config-utility", default="postconf",
            help="Path to the 'postconf' executable.")

    def __init__(self, *args, **kwargs):
        super(Installer, self).__init__(*args, **kwargs)
        self.config_dir = None
        self.proposed_changes = {}
        self.save_notes = []

    def prepare(self):
        """Prepare the installer.

        Finish up any additional initialization.

        :raises errors.PluginError: when an unexpected error occurs
        :raises errors.MisconfigurationError: when the config is invalid
        :raises errors.NoInstallationError: when can't find installation
        :raises errors.NotSupportedError: when version is not supported

        """
        for param in ("ctl", "config_utility",):
            self._verify_executable_is_available(param)
        self._set_config_dir()
        self._check_version()
        self.config_test()
        self._lock_config_dir()

    def _verify_executable_is_available(self, config_name):
        """Asserts the program in the specified config param is found.

        :param str config_name: name of the config param

        :raises .NoInstallationError: when the executable isn't found

        """
        if not certbot_util.exe_exists(self.conf(config_name)):
            if not plugins_util.path_surgery(self.conf(config_name)):
                raise errors.NoInstallationError(
                    "Cannot find executable '{0}'. You can provide the "
                    "path to this command with --{1}".format(
                        self.conf(config_name),
                        self.option_name(config_name)))

    def _set_config_dir(self):
        """Ensure self.config_dir is set to the correct path.

        If the configuration directory to use was set by the user, we'll
        use that value, otherwise, we'll find the default path using
        'postconf'.

        """
        if self.conf("config-dir") is None:
            self.config_dir = self._get_config_var("config_directory")
        else:
            self.config_dir = self.conf("config-dir")

    def _check_version(self):
        """Verifies that the installed Postfix version is supported.

        :raises errors.NotSupportedError: if the version is unsupported

        """
        if self._get_version() < (2, 6,):
            raise errors.NotSupportedError('Postfix version is too old')

    def _lock_config_dir(self):
        """Stop two Postfix plugins from modifying the config at once.

        :raises .PluginError: if unable to acquire the lock

        """
        try:
            certbot_util.lock_dir_until_exit(self.config_dir)
        except (OSError, errors.LockError):
            logger.debug("Encountered error:", exc_info=True)
            raise errors.PluginError(
                "Unable to lock %s", self.config_dir)

    def more_info(self):
        """Human-readable string to help the user.
        Should describe the steps taken and any relevant info to help the user
        decide which plugin to use.
        :rtype str:
        """
        return (
            "Configures Postfix to try to authenticate mail servers, use "
            "installed certificates and disable weak ciphers and protocols.{0}"
            "Server root: {root}{0}"
            "Version: {version}".format(
                os.linesep,
                root=self.config_dir,
                version='.'.join([str(i) for i in self._get_version()]))
        )

    def _get_version(self):
        """Return the mail version of Postfix.

        Version is returned as a tuple. (e.g. '2.11.3' is (2, 11, 3))

        :returns: version
        :rtype: tuple

        :raises .PluginError: Unable to find Postfix version.

        """
        mail_version = self._get_config_var("mail_version", default=True)
        return tuple(int(i) for i in mail_version.split('.'))

    def get_all_names(self):
        """Returns all names that may be authenticated.

        :rtype: `set` of `str`

        """
        return set(self._get_config_var(var)
                   for var in ('mydomain', 'myhostname', 'myorigin',))

    def deploy_cert(self, domain, cert_path,
                    key_path, chain_path, fullchain_path):
        """Configure the Postfix SMTP server to use the given TLS cert.

        :param str domain: domain to deploy certificate file
        :param str cert_path: absolute path to the certificate file
        :param str key_path: absolute path to the private key file
        :param str chain_path: absolute path to the certificate chain file
        :param str fullchain_path: absolute path to the certificate fullchain
            file (cert plus chain)

        :raises .PluginError: when cert cannot be deployed

        """
        # pylint: disable=unused-argument
        self.save_notes.append("Configuring TLS for {0}".format(domain))
        self._set_config_var("smtpd_tls_cert_file", fullchain_path)
        self._set_config_var("smtpd_tls_key_file", key_path)
        self._set_config_var("smtpd_tls_mandatory_protocols", "!SSLv2, !SSLv3")
        self._set_config_var("smtpd_tls_protocols", "!SSLv2, !SSLv3")
        self._set_config_var("smtpd_use_tls", "yes")

    def enhance(self, domain, enhancement, options=None):
        """Raises an exception for request for unsupported enhancement.

        :raises .PluginError: this is always raised as no enhancements
            are currently supported

        """
        # pylint: disable=unused-argument
        raise errors.PluginError(
            "Unsupported enhancement: {0}".format(enhancement))

    def supported_enhancements(self):
        """Returns a list of supported enhancements.

        :rtype: list

        """
        return []

    def save(self, title=None, temporary=False):
        """Creates backups and writes changes to configuration files.

        :param str title: The title of the save. If a title is given, the
            configuration will be saved as a new checkpoint and put in a
            timestamped directory. `title` has no effect if temporary is true.

        :param bool temporary: Indicates whether the changes made will
            be quickly reversed in the future (challenges)

        :raises errors.PluginError: when save is unsuccessful

        """
        if self.proposed_changes:
            save_files = set((os.path.join(self.config_dir, "main.cf"),))
            self.add_to_checkpoint(save_files,
                                   "\n".join(self.save_notes), temporary)
            self._write_config_changes()
            self.proposed_changes.clear()

        del self.save_notes[:]

        if title and not temporary:
            self.finalize_checkpoint(title)

    def config_test(self):
        """Make sure the configuration is valid.

        :raises .MisconfigurationError: if the config is invalid

        """
        try:
            self._run_postfix_subcommand("check")
        except subprocess.CalledProcessError:
            raise errors.MisconfigurationError(
                "Postfix failed internal configuration check.")

    def restart(self):
        """Restart or refresh the server content.

        :raises .PluginError: when server cannot be restarted

        """
        logger.info("Reloading Postfix configuration...")
        if self._is_postfix_running():
            self._reload()
        else:
            self._start()

    def _is_postfix_running(self):
        """Is Postfix currently running?

        Uses the 'postfix status' command to determine if Postfix is
        currently running using the specified configuration files.

        :returns: True if Postfix is running, otherwise, False
        :rtype: bool

        """
        try:
            self._run_postfix_subcommand("status")
        except subprocess.CalledProcessError:
            return False
        return True

    def _reload(self):
        """Instructions Postfix to reload its configuration.

        If Postfix isn't currently running, this method will fail.

        :raises .PluginError: when Postfix cannot reload

        """
        try:
            self._run_postfix_subcommand("reload")
        except subprocess.CalledProcessError:
            raise errors.PluginError(
                "Postfix failed to reload its configuration.")

    def _start(self):
        """Instructions Postfix to start running.

        :raises .PluginError: when Postfix cannot start

        """
        try:
            self._run_postfix_subcommand("start")
        except subprocess.CalledProcessError:
            raise errors.PluginError("Postfix failed to start")

    def _run_postfix_subcommand(self, subcommand):
        """Runs a subcommand of the 'postfix' control program.

        If the command fails, the exception is logged at the DEBUG
        level.

        :param str subcommand: subcommand to run

        :raises subprocess.CalledProcessError: if the command fails

        """
        cmd = [self.conf("ctl")]
        if self.conf("config-dir") is not None:
            cmd.extend(("-c", self.conf("config-dir"),))
        cmd.append(subcommand)

        util.check_call(cmd)

    def _get_config_var(self, name, default=False):
        """Return the value of the specified Postfix config parameter.

        If there is an unsaved change modifying the value of the
        specified config parameter, the value after this proposed change
        is returned rather than the current value.

        :param str name: name of the Postfix config parameter to return
        :param bool default: whether or not to return the default value
            instead of the actual value

        :returns: value of the specified configuration parameter
        :rtype: str

        """
        if not default and name in self.proposed_changes:
            return self.proposed_changes[name]
        else:
            return self.__get_config_var_from_postconf(name, default)

    def __get_config_var_from_postconf(self, name, default):
        """Return the value of the specified Postfix config parameter.

        This ignores self.proposed_changes and gets the value from
        postconf.

        :param str name: name of the Postfix config parameter to return
        :param bool default: whether or not to return the default value
            instead of the actual value

        :returns: value of the specified configuration parameter
        :rtype: str

        """
        output = self._get_raw_config_output(name, default)
        return self._clean_postconf_output(output, name)

    def _get_raw_config_output(self, name, default):
        """Returns the raw output from postconf for the specified param.

        :param str name: name of the Postfix config parameter to obtain
        :param bool default: whether or not to return the default value
            instead of the actual value

        :returns: output from postconf
        :rtype: str

        """
        cmd = self._postconf_command_base()
        if default:
            cmd.append("-d")
        cmd.append(name)

        try:
            return util.check_output(cmd)
        except subprocess.CalledProcessError:
            raise errors.PluginError(
                "Unable to determine the value "
                "of Postfix parameter {0}".format(name))

    def _clean_postconf_output(self, output, name):
        """Parses postconf output and returns the specified value.

        :param str output: output from postconf
        :param str name: name of the Postfix config parameter to obtain

        :returns: value of the specified configuration parameter
        :rtype: str

        """
        expected_prefix = name + " ="
        if not output.startswith(expected_prefix):
            raise errors.PluginError(
                "Unexpected output '{0}' from postconf".format(output))

        return output[len(expected_prefix):].strip()

    def _set_config_var(self, name, value):
        """Set the Postfix config parameter name to value.

        This method only stores the requested change in memory. The
        Postfix configuration is not modified until save() is called.
        If there's already an identical in progress change or the
        Postfix configuration parameter already has the specified value,
        no changes are made.

        :param str name: name of the Postfix config parameter
        :param str value: value to set the Postfix config parameter to

        """
        if self._get_config_var(name) != value:
            self.proposed_changes[name] = value
            self.save_notes.append("\t* Set {0} to {1}".format(name, value))

    def _write_config_changes(self):
        """Write proposed changes to the Postfix config.

        :raises errors.PluginError: if an error occurs

        """
        cmd = self._postconf_command_base()
        cmd.extend("{0}={1}".format(name, value)
                   for name, value in self.proposed_changes.items())

        try:
            util.check_call(cmd)
        except subprocess.CalledProcessError:
            raise errors.PluginError(
                "An error occurred while updating your Postfix config.")

    def _postconf_command_base(self):
        """Builds start of a postconf command using the selected config."""
        cmd = [self.conf("config-utility")]

        if self.conf("config-dir") is not None:
            cmd.extend(("-c", self.conf("config-dir"),))

        return cmd
