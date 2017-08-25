"""Certbot installer plugin for Postfix."""
import logging
import os
import string
import subprocess
import sys

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
    """Certbot installer plugin for Postfix."""

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
        self.fixup          = False
        self.config_dir     = None

    def prepare(self):
        """Prepare the installer.

        Finish up any additional initialization.

        :raises errors.PluginError: when an unexpected error occurs
        :raises errors.NoInstallationError: when can't find installation
        :raises errors.NotSupportedError: when version is not supported

        """
        for param in ("ctl", "config_dir",):
            self._verify_executable_is_available(param)
        self._set_config_dir()
        self._check_version()
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
            self.config_dir = self.get_config_var("config_directory")
        else:
            self.config_dir = self.conf("config-dir")

    def _check_version(self):
        """Verifies that the installed Postfix version is supported.

        :raises errors.NotSupportedError: if the version is unsupported

        """
        if self._get_version() < (2, 11, 0):
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
        mail_version = self.get_config_var("mail_version", default=True)
        return tuple(int(i) for i in mail_version.split('.'))

    def get_all_names(self):
        """Returns all names that may be authenticated.

        :rtype: `set` of `str`

        """
        return set(self.get_config_var(var)
                   for var in ('mydomain', 'myhostname', 'myorigin',))

    def enhance(self, domain, enhancement, options=None):
        """Raises an exception for request for unsupported enhancement.

        :raises .PluginError: this is always raised as no enhancements
            are currently supported

        """
        raise errors.PluginError(
            "Unsupported enhancement: {0}".format(enhancement))

    def supported_enhancements(self):
        """Returns a list of supported enhancements.

        :rtype: list

        """
        return []

    def ensure_cf_var(self, var, ideal, also_acceptable):
        """
        Ensure that existing postfix config @var is in the list of @acceptable
        values; if not, set it to the ideal value.

        :raises .errors.MisconfigurationError: if conflicting existing values
            are found for var

        """
        acceptable = [ideal] + also_acceptable

        l = [(num,line) for num,line in enumerate(self.cf)
             if line.startswith(var)]
        if not any(l):
            self.additions.append(var + " = " + ideal)
        else:
            values = map(parse_line, l)
            if len(set(values)) > 1:
                if self.fixup:
                    conflicting_lines = [num for num,_var,val in values]
                    self.deletions.extend(conflicting_lines)
                    self.additions.append(var + " = " + ideal)
                else:
                    raise errors.MisconfigurationError(
                        "Conflicting existing config values {0}".format(l)
                    )
            val = values[0][2]
            if val not in acceptable:
                if self.fixup:
                    self.deletions.append(values[0][0])
                    self.additions.append(var + " = " + ideal)
                else:
                    raise errors.MisconfigurationError(
                        "Existing config has %s=%s"%(var,val)
                    )

    def wrangle_existing_config(self):
        """
        Try to ensure/mutate that the config file is in a sane state.
        Fixup means we'll delete existing lines if necessary to get there.
        """
        # Check we're currently accepting inbound STARTTLS sensibly
        self.ensure_cf_var("smtpd_use_tls", "yes", [])
        # Ideally we use it opportunistically in the outbound direction
        self.ensure_cf_var("smtp_tls_security_level", "may", ["encrypt","dane"])
        # Maximum verbosity lets us collect failure information
        self.ensure_cf_var("smtp_tls_loglevel", "1", [])
        # Inject a reference to our per-domain policy map
        # policy_cf_entry = "texthash:" + self.policy_file

        # self.ensure_cf_var("smtp_tls_policy_maps", policy_cf_entry, [])
        # self.ensure_cf_var("smtp_tls_CAfile", self.ca_file, [])

        # Disable SSLv2 and SSLv3. Syntax for `smtp_tls_protocols` changed
        # between Postfix version 2.5 and 2.6, since we only support => 2.11
        # we don't use nor support legacy Postfix syntax.
        # - Server:
        self.ensure_cf_var("smtpd_tls_protocols", "!SSLv2, !SSLv3", [])
        self.ensure_cf_var("smtpd_tls_mandatory_protocols", "!SSLv2, !SSLv3", [])
        # - Client:
        self.ensure_cf_var("smtp_tls_protocols", "!SSLv2, !SSLv3", [])
        self.ensure_cf_var("smtp_tls_mandatory_protocols", "!SSLv2, !SSLv3", [])

    def maybe_add_config_lines(self):
        if not self.additions:
            return
        if self.fixup:
            logger.info('Deleting lines: {}'.format(self.deletions))
        self.additions[:0]=["#",
                            "# New config lines added by STARTTLS Everywhere",
                            "#"]
        new_cf_lines = "\n".join(self.additions) + "\n"
        logger.info('Adding to {}:'.format(self.fn))
        logger.info(new_cf_lines)
        if self.raw_cf[-1][-1] == "\n":         sep = ""
        else:                                   sep = "\n"

        for num, line in enumerate(self.raw_cf):
            if self.fixup and num in self.deletions:
                self.new_cf += "# Line removed by STARTTLS Everywhere\n# " + line
            else:
                self.new_cf += line
        self.new_cf += sep + new_cf_lines

        with open(self.fn, "w") as f:
            f.write(self.new_cf)

    def deploy_cert(self, domain, _cert_path, key_path, _chain_path, fullchain_path):
        """Deploy certificate.
        :param str domain: domain to deploy certificate file
        :param str cert_path: absolute path to the certificate file
        :param str key_path: absolute path to the private key file
        :param str chain_path: absolute path to the certificate chain file
        :param str fullchain_path: absolute path to the certificate fullchain
            file (cert plus chain)
        :raises .PluginError: when cert cannot be deployed
        """
        self.wrangle_existing_config()
        self.ensure_cf_var("smtpd_tls_cert_file", fullchain_path, [])
        self.ensure_cf_var("smtpd_tls_key_file", key_path, [])
        self.set_domainwise_tls_policies()
        self.update_CAfile()

    def save(self, title=None, temporary=False):
        """Saves all changes to the configuration files.
        Both title and temporary are needed because a save may be
        intended to be permanent, but the save is not ready to be a full
        checkpoint. If an exception is raised, it is assumed a new
        checkpoint was not created.
        :param str title: The title of the save. If a title is given, the
            configuration will be saved as a new checkpoint and put in a
            timestamped directory. `title` has no effect if temporary is true.
        :param bool temporary: Indicates whether the changes made will
            be quickly reversed in the future (challenges)
        :raises .PluginError: when save is unsuccessful
        """
        self.maybe_add_config_lines()

    def config_test(self):
        """Make sure the configuration is valid.
        :raises .MisconfigurationError: when the config is not in a usable state
        """
        if os.geteuid() != 0:
            rc = os.system('sudo /usr/sbin/postfix check')
        else:
            rc = os.system('/usr/sbin/postfix check')
        if rc != 0:
            raise errors.MisconfigurationError('Postfix failed self-check.')

    def restart(self):
        """Restart or refresh the server content.
        :raises .PluginError: when server cannot be restarted
        """
        logger.info('Reloading postfix config...')
        if os.geteuid() != 0:
            rc = os.system("sudo service postfix reload")
        else:
            rc = os.system("service postfix reload")
        if rc != 0:
            raise errors.MisconfigurationError('cannot restart postfix')

    def get_config_var(self, name, default=False):
        """Return the value of the specified Postfix config parameter.

        :param str name: name of the Postfix config parameter to return
        :param bool default: whether or not to return the default value
            instead of the actual value

        :returns: value of the specified configuration parameter
        :rtype: str

        """
        cmd = self._build_cmd_for_config_var(name, default)

        try:
            output = util.check_output(cmd)
        except subprocess.CalledProcessError:
            logger.debug("Encountered an error when running 'postconf'",
                         exc_info=True)
            raise errors.PluginError(
                "Unable to determine the value "
                "of Postfix parameter {0}".format(name))

        expected_prefix = name + " ="
        if not output.startswith(expected_prefix):
            raise errors.PluginError(
                "Unexpected output '{0}' from '{1}'".format(output,
                                                            ' '.join(cmd)))

        return output[len(expected_prefix):].strip()

    def _build_cmd_for_config_var(self, name, default):
        """Return a command to run to get a Postfix config parameter.

        :param str name: name of the Postfix config parameter to return
        :param bool default: whether or not to return the default value
            instead of the actual value

        :returns: command to run
        :rtype: list

        """
        cmd = [self.conf("config-utility")]

        if self.conf("config-dir") is not None:
            cmd.extend(("-c", self.conf("config-dir"),))

        if default:
            cmd.append("-d")

        cmd.append(name)

        return cmd


    # def update_CAfile(self):
    #     os.system("cat /usr/share/ca-certificates/mozilla/*.crt > " + self.ca_file)
    #
    # def set_domainwise_tls_policies(self):
    #     all_acceptable_mxs = self.policy_config.acceptable_mxs
    #     for address_domain, properties in all_acceptable_mxs.items():
    #         mx_list = properties.accept_mx_domains
    #         if len(mx_list) > 1:
    #             logger.warn('Lists of multiple accept-mx-domains not yet '
    #                         'supported.')
    #             logger.warn('Using MX {} for {}'.format(mx_list[0],
    #                                                     address_domain)
    #                        )
    #             logger.warn('Ignoring: {}'.format(', '.join(mx_list[1:])))
    #         mx_domain = mx_list[0]
    #         mx_policy = self.policy_config.get_tls_policy(mx_domain)
    #         entry = address_domain + " encrypt"
    #         if mx_policy.min_tls_version.lower() == "tlsv1":
    #             entry += " protocols=!SSLv2:!SSLv3"
    #         elif mx_policy.min_tls_version.lower() == "tlsv1.1":
    #             entry += " protocols=!SSLv2:!SSLv3:!TLSv1"
    #         elif mx_policy.min_tls_version.lower() == "tlsv1.2":
    #             entry += " protocols=!SSLv2:!SSLv3:!TLSv1:!TLSv1.1"
    #         else:
    #             logger.warn('Unknown minimum TLS version: {} '.format(
    #                 mx_policy.min_tls_version)
    #             )
    #         self.policy_lines.append(entry)

    #     with open(self.policy_file, "w") as f:
    #         f.write("\n".join(self.policy_lines) + "\n")


def parse_line(line_data):
    """
    Return the (line number, left hand side, right hand side) of a stripped
    postfix config line.

    Lines are like:
    smtpd_tls_session_cache_database = btree:${data_directory}/smtpd_scache
    """
    num,line = line_data
    left, sep, right = line.partition("=")
    if not sep:
        return None
    return (num, left.strip(), right.strip())
