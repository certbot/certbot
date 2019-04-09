"""certbot installer plugin for postfix."""
import logging
import os

import zope.interface
import zope.component
import six

from certbot import errors
from certbot import interfaces
from certbot import util as certbot_util
from certbot.plugins import common as plugins_common

from certbot_postfix import constants
from certbot_postfix import postconf
from certbot_postfix import util

# pylint: disable=unused-import, no-name-in-module
from acme.magic_typing import Callable, Dict, List
# pylint: enable=unused-import, no-name-in-module

logger = logging.getLogger(__name__)

@zope.interface.implementer(interfaces.IInstaller)
@zope.interface.provider(interfaces.IPluginFactory)
class Installer(plugins_common.Installer):
    """Certbot installer plugin for Postfix.

    :ivar str config_dir: Postfix configuration directory to modify
    :ivar list save_notes: documentation for proposed changes. This is
        cleared and stored in Certbot checkpoints when save() is called

    :ivar postconf: Wrapper for Postfix configuration command-line tool.
    :type postconf: :class: `certbot_postfix.postconf.ConfigMain`
    :ivar postfix: Wrapper for Postfix command-line tool.
    :type postfix: :class: `certbot_postfix.util.PostfixUtil`
    """

    description = "Configure TLS with the Postfix MTA"

    @classmethod
    def add_parser_arguments(cls, add):
        add("ctl", default=constants.CLI_DEFAULTS["ctl"],
            help="Path to the 'postfix' control program.")
        # This directory points to Postfix's configuration directory.
        add("config-dir", default=constants.CLI_DEFAULTS["config_dir"],
            help="Path to the directory containing the "
            "Postfix main.cf file to modify instead of using the "
            "default configuration paths.")
        add("config-utility", default=constants.CLI_DEFAULTS["config_utility"],
            help="Path to the 'postconf' executable.")
        add("tls-only", action="store_true", default=constants.CLI_DEFAULTS["tls_only"],
            help="Only set params to enable opportunistic TLS and install certificates.")
        add("server-only", action="store_true", default=constants.CLI_DEFAULTS["server_only"],
            help="Only set server params (prefixed with smtpd*)")
        add("ignore-master-overrides", action="store_true",
            default=constants.CLI_DEFAULTS["ignore_master_overrides"],
            help="Ignore errors reporting overridden TLS parameters in master.cf.")

    def __init__(self, *args, **kwargs):
        super(Installer, self).__init__(*args, **kwargs)
        # Wrapper around postconf commands
        self.postfix = None
        self.postconf = None

        # Files to save
        self.save_notes = [] # type: List[str]

        self._enhance_func = {} # type: Dict[str, Callable[[str, str], None]]
        # Since we only need to enable TLS once for all domains,
        # keep track of whether this enhancement was already called.
        self._tls_enabled = False

    def prepare(self):
        """Prepare the installer.

        :raises errors.PluginError: when an unexpected error occurs
        :raises errors.MisconfigurationError: when the config is invalid
        :raises errors.NoInstallationError: when can't find installation
        :raises errors.NotSupportedError: when version is not supported
        """
        # Verify postfix and postconf are installed
        for param in ("ctl", "config_utility",):
            util.verify_exe_exists(self.conf(param),
                    "Cannot find executable '{0}'. You can provide the "
                    "path to this command with --{1}".format(
                        self.conf(param),
                        self.option_name(param)))

        # Set up CLI tools
        self.postfix = util.PostfixUtil(self.conf('config-dir'))
        self.postconf = postconf.ConfigMain(self.conf('config-utility'),
                                            self.conf('ignore-master-overrides'),
                                            self.conf('config-dir'))

        # Ensure current configuration is valid.
        self.config_test()

        # Check Postfix version
        self._check_version()
        self._lock_config_dir()
        self.install_ssl_dhparams()

    def config_test(self):
        """Test to see that the current Postfix configuration is valid.

        :raises errors.MisconfigurationError: If the configuration is invalid.
        """
        self.postfix.test()

    def _check_version(self):
        """Verifies that the installed Postfix version is supported.

        :raises errors.NotSupportedError: if the version is unsupported
        """
        if self._get_version() < constants.MINIMUM_VERSION:
            version_string = '.'.join([str(n) for n in constants.MINIMUM_VERSION])
            raise errors.NotSupportedError('Postfix version must be at least %s' % version_string)

    def _lock_config_dir(self):
        """Stop two Postfix plugins from modifying the config at once.

        :raises .PluginError: if unable to acquire the lock
        """
        try:
            certbot_util.lock_dir_until_exit(self.conf('config-dir'))
        except (OSError, errors.LockError):
            logger.debug("Encountered error:", exc_info=True)
            raise errors.PluginError(
                "Unable to lock %s" % self.conf('config-dir'))

    def more_info(self):
        """Human-readable string to help the user. Describes steps taken and any relevant
        info to help the user decide which plugin to use.

        :rtype: str
        """
        return (
            "Configures Postfix to try to authenticate mail servers, use "
            "installed certificates and disable weak ciphers and protocols.{0}"
            "Server root: {root}{0}"
            "Version: {version}".format(
                os.linesep,
                root=self.conf('config-dir'),
                version='.'.join([str(i) for i in self._get_version()]))
        )

    def _get_version(self):
        """Return the version of Postfix, as a tuple. (e.g. '2.11.3' is (2, 11, 3))

        :returns: version
        :rtype: tuple

        :raises errors.PluginError: Unable to find Postfix version.
        """
        mail_version = self.postconf.get_default("mail_version")
        return tuple(int(i) for i in mail_version.split('.'))

    def get_all_names(self):
        """Returns all names that may be authenticated.

        :rtype: `set` of `str`

        """
        return certbot_util.get_filtered_names(self.postconf.get(var)
                   for var in ('mydomain', 'myhostname', 'myorigin',))

    def _set_vars(self, var_dict):
        """Sets all parameters in var_dict to config file. If current value is already set
        as more secure (acceptable), then don't set/overwrite it.
        """
        for param, acceptable in six.iteritems(var_dict):
            if not util.is_acceptable_value(param, self.postconf.get(param), acceptable):
                self.postconf.set(param, acceptable[0], acceptable)

    def _confirm_changes(self):
        """Confirming outstanding updates for configuration parameters.

        :raises errors.PluginError: when user rejects the configuration changes.
        """
        updates = self.postconf.get_changes()
        output_string = "Postfix TLS configuration parameters to update in main.cf:\n"
        for name, value in six.iteritems(updates):
            output_string += "{0} = {1}\n".format(name, value)
        output_string += "Is this okay?\n"
        if not zope.component.getUtility(interfaces.IDisplay).yesno(output_string,
            force_interactive=True, default=True):
            raise errors.PluginError(
                "Manually rejected configuration changes.\n"
                "Try using --tls-only or --server-only to change a particular"
                "subset of configuration parameters.")

    def deploy_cert(self, domain, cert_path,
                    key_path, chain_path, fullchain_path):  # pylint: disable=unused-argument
        """Configure the Postfix SMTP server to use the given TLS cert.

        :param str domain: domain to deploy certificate file
        :param str cert_path: absolute path to the certificate file
        :param str key_path: absolute path to the private key file
        :param str chain_path: absolute path to the certificate chain file
        :param str fullchain_path: absolute path to the certificate fullchain
            file (cert plus chain)

        :raises .PluginError: when cert cannot be deployed

        """
        if self._tls_enabled:
            return
        self._tls_enabled = True
        self.save_notes.append("Configuring TLS for {0}".format(domain))
        self.postconf.set("smtpd_tls_cert_file", cert_path)
        self.postconf.set("smtpd_tls_key_file", key_path)
        self._set_vars(constants.TLS_SERVER_VARS)
        if not self.conf('server_only'):
            self._set_vars(constants.TLS_CLIENT_VARS)
        if not self.conf('tls_only'):
            self._set_vars(constants.DEFAULT_SERVER_VARS)
            if not self.conf('server_only'):
                self._set_vars(constants.DEFAULT_CLIENT_VARS)
            # Despite the name, this option also supports 2048-bit DH params.
            # http://www.postfix.org/FORWARD_SECRECY_README.html#server_fs
            self.postconf.set("smtpd_tls_dh1024_param_file", self.ssl_dhparams)
        self._confirm_changes()

    def enhance(self, domain, enhancement, options=None):  # pylint: disable=unused-argument
        """Raises an exception since this installer doesn't support any enhancements.
        """
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
        save_files = set((os.path.join(self.conf('config-dir'), "main.cf"),))
        self.add_to_checkpoint(save_files,
                               "\n".join(self.save_notes), temporary)
        self.postconf.flush()

        del self.save_notes[:]

        if title and not temporary:
            self.finalize_checkpoint(title)

    def recovery_routine(self):
        super(Installer, self).recovery_routine()
        self.postconf = postconf.ConfigMain(self.conf('config-utility'),
                                            self.conf('ignore-master-overrides'),
                                            self.conf('config-dir'))

    def rollback_checkpoints(self, rollback=1):
        """Rollback saved checkpoints.

        :param int rollback: Number of checkpoints to revert

        :raises .errors.PluginError: If there is a problem with the input or
            the function is unable to correctly revert the configuration
        """
        super(Installer, self).rollback_checkpoints(rollback)
        self.postconf = postconf.ConfigMain(self.conf('config-utility'),
                                            self.conf('ignore-master-overrides'),
                                            self.conf('config-dir'))

    def restart(self):
        """Restart or refresh the server content.

        :raises .PluginError: when server cannot be restarted
        """
        self.postfix.restart()
