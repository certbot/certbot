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

from certbot_postfix import postconf
from certbot_postfix import util

from policylist import policy

POLICY_FILENAME = "starttls_everywhere_policy"

CA_CERTS_PATH = "/etc/ssl/certs/"

# If the value of a default VAR is a tuple, then the values which
# come LATER in the tuple are more strict/more secure.
# Certbot will default to the first value in the tuple, but will
# not override "more secure" settings.

ACCEPTABLE_SECURITY_LEVELS = ("may", "encrypt")
ACCEPTABLE_CIPHER_LEVELS = ("medium", "high")

TLS_VERSIONS = ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2")
# Should NOT use SSLv2/3.
ACCEPTABLE_TLS_VERSIONS = ("TLSv1", "TLSv1.1", "TLSv1.2")

# Default variables for a secure MTA server [receiver].
DEFAULT_SERVER_VARS = {
    "smtpd_tls_mandatory_protocols": "!SSLv2, !SSLv3",
    "smtpd_tls_protocols": "!SSLv2, !SSLv3",
    "smtpd_tls_security_level": ACCEPTABLE_SECURITY_LEVELS,
    "smtpd_tls_ciphers": ACCEPTABLE_CIPHER_LEVELS,
    "smtpd_tls_eecdh_grade": "strong",
}

# Default variables for a secure MTA client [sender].
DEFAULT_CLIENT_VARS = {
    "smtp_tls_security_level": ACCEPTABLE_SECURITY_LEVELS,
    "smtp_tls_ciphers": ACCEPTABLE_CIPHER_LEVELS,
}

logger = logging.getLogger(__name__)

def _report_master_overrides_less_secure(acceptable):
    def _report_master_overrides(name, overrides):
        for override in overrides:
            if override not in acceptable:
                print("Warning: Parameter %s is overridden as less-secure option %s " + 
                      "for service %s in master configuration file!" %
                      (name, override[1], override[0]))

def _report_master_overrides(name, overrides):
    for override in overrides:
        print("Warning: Parameter %s is overridden as %s for service %s in master configuration file!" %
                (name, override[1], override[0]))

def _get_formatted_protocols(min_tls_version, delimiter=":"):
    """Enforces the minimum TLS version in a way that Postfix can understand. For instance,
    if the min_tls_version is TLS1.1, then Postfix expects: "!SSLv2:!SSLv3:!TLSv1"

    :param str min_tls_version: SSL/TLS version that we expect to be in ACCEPTABLE_TLS_VERSIONS.
    :param str delimiter: delimiter for the SSL/TLS declarations.
    :rtype str: Protocol declaration, formatted correctly in a Postfix-y way. For instance:
        TLSv1.1 => !SSLv2:!SSLv3:!TLSv1
        TLSv1   => !SSLv2:!SSLv3
    """
    if min_tls_version not in TLS_VERSIONS or min_tls_version not in ACCEPTABLE_TLS_VERSIONS:
        return None
    return delimiter.join(["!" + version for version in TLS_VERSIONS[0:TLS_VERSIONS.index(min_tls_version)]])

def _get_formatted_policy_for_domain(address_domain, tls_policy):
    """Parses TLS policy specification into a format that Postfix expects. In particular:
        <domain> <tls_security_level> protocols=<protocols>
    For instance, let's say we have an entry for mail.example.com with a minimum TLS version of 1.1:
        mail.example.com encrypt protocols=!SSLv2:!SSLv3:!TLSv1
    :param address_domain str: The domain we're configuring this policy for.
    :param tls_policy dict: TLS policy information.
    :rtype str: Properly formatted Postfix TLS policy specification for this domain.
    """
    mx_list = tls_policy['mxs']
    # TODO(sydneyli): enable `verify` mode.
    if len(mx_list) == 0:
        matches = ""
    else:
        matches = ':'.join(mx_list)
    entry = address_domain + " secure " + matches
    protocols_value = _get_formatted_protocols(tls_policy['min-tls-version'])
    if protocols_value is not None:
        entry += " protocols=" + protocols_value
    else:
        logger.warn('Unknown minimum TLS version: {} '.format(
            mx_policy.min_tls_version))
    return entry


@zope.interface.implementer(interfaces.IInstaller)
@zope.interface.provider(interfaces.IPluginFactory)
class Installer(plugins_common.Installer):
    """Certbot installer plugin for Postfix.

    :ivar str config_dir: Postfix configuration directory to modify
    :ivar list save_notes: documentation for proposed changes. This is
        cleared and stored in Certbot checkpoints when save() is called
    :ivar postconf: Wrapper for Postfix configuration command-line tool.
    :ivar policy: A STARTTLS Policy object to query per-domain TLS policies.
    :ivar policy_file: TLS policy file in a format that Postfix expects.
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
        add("policy-file", help="Name of the policy file that we should write to in config-dir.",
                           default=POLICY_FILENAME)

    def __init__(self, *args, **kwargs):
        super(Installer, self).__init__(*args, **kwargs)
        self.config_dir = None
        self.postconf = None
        self.save_notes = []
        self.policy = None
        self.policy_file = None

    def write_domainwise_tls_policies(self, fopen=open):
        """Writes domainwise tls policies to self.policy_file in a format that Postfix
        can parse.
        """
        policy_lines = []
        all_tls_policies = self.policy.tls_policies
        for address_domain, tls_policy in all_tls_policies.items():
            policy_lines.append(_get_formatted_policy_for_domain(address_domain, tls_policy))
        with fopen(self.policy_file, "w") as f:
            f.write("\n".join(policy_lines) + "\n")

    def _ensure_ca_certificates_exist(self):
        # TODO (sydneyli): Ensure `ca-certificates` is installed correctly, or that
        # /etc/ssl/certs/ even has certificates in it, probably via a sanity check using
        # `openssl` command?
        pass

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
        self._ensure_ca_certificates_exist()
        self.postconf = postconf.ConfigMain(self.conf('config-utility'))
        self._set_config_dir()
        self.postfix = util.PostfixUtil(self.config_dir)
        self.policy_file = self.conf("policy-file")
        self.policy = policy.Config()
        self.policy.load()
        self._check_version()
        self.postfix.test()
        self._lock_config_dir()
        self.policy_file = os.path.join(self.config_dir, POLICY_FILENAME)
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
        for param, acceptable in var_dict.iteritems():
            if isinstance(acceptable, tuple):
                if self.postconf.get(param) not in acceptable:
                    self.postconf.set(param, acceptable[0],
                        _report_master_overrides_less_secure(acceptable))
            else:
                self.postconf.set(param, acceptable,
                    _report_master_overrides_less_secure([acceptable]))

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
        self.postconf.set("smtpd_tls_cert_file", fullchain_path, check_override=_report_master_overrides)
        self.postconf.set("smtpd_tls_key_file", key_path, _report_master_overrides)
        self._set_vars(DEFAULT_SERVER_VARS)
        self._set_vars(DEFAULT_CLIENT_VARS)
        self.write_domainwise_tls_policies()
        policy_cf_entry = "texthash:" + self.policy_file
        self.postconf.set("smtp_tls_policy_maps", policy_cf_entry)
        self.postconf.set("smtp_tls_CApath", CA_CERTS_PATH, _report_master_overrides) 

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

