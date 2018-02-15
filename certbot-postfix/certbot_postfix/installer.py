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
from certbot_postfix import postconf

import starttls_policy

POLICY_FILENAME = "starttls_everywhere_policy"
CA_FILENAME = "starttls_everywhere_CAfile"

acceptable_security_levels = ("may", "encrypt")
acceptable_cipher_levels = ("medium", "high")

default_server_vars = {
    "smtpd_tls_mandatory_protocols": "!SSLv2, !SSLv3",
    "smtpd_tls_protocols": "!SSLv2, !SSLv3",
    "smtpd_tls_security_level": acceptable_security_levels,
    "smtpd_tls_ciphers": acceptable_cipher_levels,
    "smtpd_tls_eecdh_grade": "strong",
}

    # "smtpd_tls_received_header": "yes",
default_client_vars = {
    "smtp_tls_security_level": acceptable_security_levels,
    "smtp_tls_ciphers": acceptable_cipher_levels,
}

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
    # Default algorithm is RSA; once we can support EC lineages, turn that on

    @classmethod
    def add_parser_arguments(cls, add):
        add("ctl", default="postfix",
            help="Path to the 'postfix' control program.")
        add("config-dir", help="Path to the directory containing the "
            "Postfix main.cf file to modify instead of using the "
            "default configuration paths.")
        add("config-utility", default="postconf",
            help="Path to the 'postconf' executable.")
        add("policy-file", default="config.json")

    def __init__(self, *args, **kwargs):
        super(Installer, self).__init__(*args, **kwargs)
        self.config_dir = None
        self.postconf = None
        # self.proposed_changes = {}
        self.save_notes = []
        self.policy = None
        self.policy_lines = []
        self.policy_file = None
        self.postfix_policy_file = None

    def set_domainwise_tls_policies(self, fopen=open):
        all_acceptable_mxs = self.policy.acceptable_mxs
        for address_domain, properties in all_acceptable_mxs.items():
            mx_list = properties.accept_mx_domains
            if len(mx_list) > 1:
                logger.warn('Lists of multiple accept-mx-domains not yet '
                            'supported.')
                logger.warn('Using MX {} for {}'.format(mx_list[0],
                                                        address_domain)
                           )
                logger.warn('Ignoring: {}'.format(', '.join(mx_list[1:])))
            mx_domain = mx_list[0]
            mx_policy = self.policy.get_tls_policy(mx_domain)
            entry = address_domain + " encrypt"
            if mx_policy.min_tls_version.lower() == "tlsv1":
                entry += " protocols=!SSLv2:!SSLv3"
            elif mx_policy.min_tls_version.lower() == "tlsv1.1":
                entry += " protocols=!SSLv2:!SSLv3:!TLSv1"
            elif mx_policy.min_tls_version.lower() == "tlsv1.2":
                entry += " protocols=!SSLv2:!SSLv3:!TLSv1:!TLSv1.1"
            else:
                logger.warn('Unknown minimum TLS version: {} '.format(
                    mx_policy.min_tls_version)
                )
            self.policy_lines.append(entry)
        with fopen(self.policy_file, "w") as f:
            f.write("\n".join(self.policy_lines) + "\n")

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
        # Set initially here so we can grab configuration directory if needed.
        self.postconf = postconf.ConfigMain(self.conf('config-utility'))
        self._set_config_dir()
        self.postfix = util.PostfixUtil(self.config_dir)
        self.policy_file = self.conf("policy-file")
        self.policy = starttls_policy.Config()
        self.policy.load_from_json_file(self.policy_file)
        self._check_version()
        self.postfix.test()
        self._lock_config_dir()
        self.postfix_policy_file = os.path.join(self.config_dir, POLICY_FILENAME)
        self.ca_file = os.path.join(self.config_dir, CA_FILENAME)
        self.postconf = postconf.ConfigMain(self.conf('config-utility'), self.config_dir)

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
            self.config_dir = self.postconf.get("config_directory")
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
        except (OSError, errors.LockError) as e:
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
        mail_version = self.postconf.get_default("mail_version")
        return tuple(int(i) for i in mail_version.split('.'))

    def get_all_names(self):
        """Returns all names that may be authenticated.

        :rtype: `set` of `str`

        """
        return certbot_util.get_filtered_names(self.postconf.get(var)
                   for var in ('mydomain', 'myhostname', 'myorigin',))

    def _set_vars(self, var_dict):
        """Sets all parameters in var_dict to config file.
        """
        for param, value in var_dict.iteritems():
            if isinstance(value, tuple):
                if self.postconf.get(param) not in value:
                    self.postconf.set(param, value[0])
            else:
                self.postconf.set(param, value)

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
        self.postconf.set("smtpd_tls_cert_file", fullchain_path)
        self.postconf.set("smtpd_tls_key_file", key_path)
        self._set_vars(default_server_vars)
        self._set_vars(default_client_vars)
        self.set_domainwise_tls_policies()
        policy_cf_entry = "texthash:" + self.postfix_policy_file
        self.postconf.set("smtp_tls_policy_maps", policy_cf_entry)
        self.postconf.set("smtp_tls_CAfile", self.ca_file)
        self._update_CAfile()

    def _update_CAfile(self):
        # TODO (sydneyli): Discover this directory or ask for user input.
        os.system("cat /usr/share/ca-certificates/mozilla/*.crt > " + self.ca_file)

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
        save_files = set((os.path.join(self.config_dir, "main.cf"),))
        self.add_to_checkpoint(save_files,
                               "\n".join(self.save_notes), temporary)
        self.postconf.flush()

        del self.save_notes[:]

        if title and not temporary:
            self.finalize_checkpoint(title)

    def restart(self):
        """Restart or refresh the server content.

        :raises .PluginError: when server cannot be restarted
        """
        self.postfix.restart()

