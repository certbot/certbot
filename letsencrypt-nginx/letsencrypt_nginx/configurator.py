"""Nginx Configuration"""
import logging
import os
import re
import shutil
import socket
import subprocess
import time

import OpenSSL
import zope.interface

from acme import challenges
from acme import crypto_util as acme_crypto_util

from letsencrypt import constants as core_constants
from letsencrypt import crypto_util
from letsencrypt import errors
from letsencrypt import interfaces
from letsencrypt import le_util
from letsencrypt import reverter

from letsencrypt.plugins import common

from letsencrypt_nginx import constants
from letsencrypt_nginx import tls_sni_01
from letsencrypt_nginx import obj
from letsencrypt_nginx import parser


logger = logging.getLogger(__name__)


class NginxConfigurator(common.Plugin):
    # pylint: disable=too-many-instance-attributes,too-many-public-methods
    """Nginx configurator.

    .. todo:: Add proper support for comments in the config. Currently,
        config files modified by the configurator will lose all their comments.

    :ivar config: Configuration.
    :type config: :class:`~letsencrypt.interfaces.IConfig`

    :ivar parser: Handles low level parsing
    :type parser: :class:`~letsencrypt_nginx.parser`

    :ivar str save_notes: Human-readable config change notes

    :ivar reverter: saves and reverts checkpoints
    :type reverter: :class:`letsencrypt.reverter.Reverter`

    :ivar tup version: version of Nginx

    """
    zope.interface.implements(interfaces.IAuthenticator, interfaces.IInstaller)
    zope.interface.classProvides(interfaces.IPluginFactory)

    description = "Nginx Web Server - currently doesn't work"

    @classmethod
    def add_parser_arguments(cls, add):
        add("server-root", default=constants.CLI_DEFAULTS["server_root"],
            help="Nginx server root directory.")
        add("ctl", default=constants.CLI_DEFAULTS["ctl"], help="Path to the "
            "'nginx' binary, used for 'configtest' and retrieving nginx "
            "version number.")

    @property
    def nginx_conf(self):
        """Nginx config file path."""
        return os.path.join(self.conf("server_root"), "nginx.conf")

    def __init__(self, *args, **kwargs):
        """Initialize an Nginx Configurator.

        :param tup version: version of Nginx as a tuple (1, 4, 7)
            (used mostly for unittesting)

        """
        version = kwargs.pop("version", None)
        super(NginxConfigurator, self).__init__(*args, **kwargs)

        # Verify that all directories and files exist with proper permissions
        self._verify_setup()

        # Files to save
        self.save_notes = ""

        # Add number of outstanding challenges
        self._chall_out = 0

        # These will be set in the prepare function
        self.parser = None
        self.version = version
        self._enhance_func = {"redirect": self._enable_redirect}

        # Set up reverter
        self.reverter = reverter.Reverter(self.config)
        self.reverter.recovery_routine()

    @property
    def mod_ssl_conf(self):
        """Full absolute path to SSL configuration file."""
        return os.path.join(self.config.config_dir, constants.MOD_SSL_CONF_DEST)

    # This is called in determine_authenticator and determine_installer
    def prepare(self):
        """Prepare the authenticator/installer.

        :raises .errors.NoInstallationError: If Nginx ctl cannot be found
        :raises .errors.MisconfigurationError: If Nginx is misconfigured
        """
        # Verify Nginx is installed
        if not le_util.exe_exists(self.conf('ctl')):
            raise errors.NoInstallationError

        # Make sure configuration is valid
        self.config_test()

        self.parser = parser.NginxParser(
            self.conf('server-root'), self.mod_ssl_conf)

        # Set Version
        if self.version is None:
            self.version = self.get_version()

        temp_install(self.mod_ssl_conf)

    # Entry point in main.py for installing cert
    def deploy_cert(self, domain, cert_path, key_path,
                    chain_path=None, fullchain_path=None):
        # pylint: disable=unused-argument
        """Deploys certificate to specified virtual host.

        .. note:: Aborts if the vhost is missing ssl_certificate or
            ssl_certificate_key.

        .. note:: Nginx doesn't have a cert chain directive.
            It expects the cert file to have the concatenated chain.
            However, we use the chain file as input to the
            ssl_trusted_certificate directive, used for verify OCSP responses.

        .. note:: This doesn't save the config files!

        :raises errors.PluginError: When unable to deploy certificate due to
            a lack of directives or configuration

        """
        if not fullchain_path:
            raise errors.PluginError(
                "The nginx plugin currently requires --fullchain-path to "
                "install a cert.")

        vhost = self.choose_vhost(domain)
        cert_directives = [['ssl_certificate', fullchain_path],
                           ['ssl_certificate_key', key_path]]

        # OCSP stapling was introduced in Nginx 1.3.7. If we have that version
        # or greater, add config settings for it.
        stapling_directives = []
        if self.version >= (1, 3, 7):
            stapling_directives = [
                ['ssl_trusted_certificate', chain_path],
                ['ssl_stapling', 'on'],
                ['ssl_stapling_verify', 'on']]

        if len(stapling_directives) != 0 and not chain_path:
            raise errors.PluginError(
                "--chain-path is required to enable "
                "Online Certificate Status Protocol (OCSP) stapling "
                "on nginx >= 1.3.7.")

        try:
            self.parser.add_server_directives(vhost.filep, vhost.names,
                                              cert_directives, replace=True)
            self.parser.add_server_directives(vhost.filep, vhost.names,
                                              stapling_directives, replace=False)
            logger.info("Deployed Certificate to VirtualHost %s for %s",
                        vhost.filep, vhost.names)
        except errors.MisconfigurationError as error:
            logger.debug(error)
            logger.warn(
                "Cannot find a cert or key directive in %s for %s. "
                "VirtualHost was not modified.", vhost.filep, vhost.names)
            # Presumably break here so that the virtualhost is not modified
            return False

        self.save_notes += ("Changed vhost at %s with addresses of %s\n" %
                            (vhost.filep,
                             ", ".join(str(addr) for addr in vhost.addrs)))
        self.save_notes += "\tssl_certificate %s\n" % fullchain_path
        self.save_notes += "\tssl_certificate_key %s\n" % key_path

    #######################
    # Vhost parsing methods
    #######################
    def choose_vhost(self, target_name):
        """Chooses a virtual host based on the given domain name.

        .. note:: This makes the vhost SSL-enabled if it isn't already. Follows
            Nginx's server block selection rules preferring blocks that are
            already SSL.

        .. todo:: This should maybe return list if no obvious answer
            is presented.

        .. todo:: The special name "$hostname" corresponds to the machine's
            hostname. Currently we just ignore this.

        :param str target_name: domain name

        :returns: ssl vhost associated with name
        :rtype: :class:`~letsencrypt_nginx.obj.VirtualHost`

        """
        vhost = None

        matches = self._get_ranked_matches(target_name)
        if not matches:
            # No matches. Create a new vhost with this name in nginx.conf.
            filep = self.parser.loc["root"]
            new_block = [['server'], [['server_name', target_name]]]
            self.parser.add_http_directives(filep, new_block)
            vhost = obj.VirtualHost(filep, set([]), False, True,
                                    set([target_name]), list(new_block[1]))
        elif matches[0]['rank'] in xrange(2, 6):
            # Wildcard match - need to find the longest one
            rank = matches[0]['rank']
            wildcards = [x for x in matches if x['rank'] == rank]
            vhost = max(wildcards, key=lambda x: len(x['name']))['vhost']
        else:
            vhost = matches[0]['vhost']

        if vhost is not None:
            if not vhost.ssl:
                self._make_server_ssl(vhost)

        return vhost

    def _get_ranked_matches(self, target_name):
        """Returns a ranked list of vhosts that match target_name.
        The ranking gives preference to SSL vhosts.

        :param str target_name: The name to match
        :returns: list of dicts containing the vhost, the matching name, and
            the numerical rank
        :rtype: list

        """
        # Nginx chooses a matching server name for a request with precedence:
        # 1. exact name match
        # 2. longest wildcard name starting with *
        # 3. longest wildcard name ending with *
        # 4. first matching regex in order of appearance in the file
        matches = []
        for vhost in self.parser.get_vhosts():
            name_type, name = parser.get_best_match(target_name, vhost.names)
            if name_type == 'exact':
                matches.append({'vhost': vhost,
                                'name': name,
                                'rank': 0 if vhost.ssl else 1})
            elif name_type == 'wildcard_start':
                matches.append({'vhost': vhost,
                                'name': name,
                                'rank': 2 if vhost.ssl else 3})
            elif name_type == 'wildcard_end':
                matches.append({'vhost': vhost,
                                'name': name,
                                'rank': 4 if vhost.ssl else 5})
            elif name_type == 'regex':
                matches.append({'vhost': vhost,
                                'name': name,
                                'rank': 6 if vhost.ssl else 7})
        return sorted(matches, key=lambda x: x['rank'])

    def get_all_names(self):
        """Returns all names found in the Nginx Configuration.

        :returns: All ServerNames, ServerAliases, and reverse DNS entries for
                  virtual host addresses
        :rtype: set

        """
        all_names = set()

        for vhost in self.parser.get_vhosts():
            all_names.update(vhost.names)

            for addr in vhost.addrs:
                host = addr.get_addr()
                if common.hostname_regex.match(host):
                    # If it's a hostname, add it to the names.
                    all_names.add(host)
                elif not common.private_ips_regex.match(host):
                    # If it isn't a private IP, do a reverse DNS lookup
                    # TODO: IPv6 support
                    try:
                        socket.inet_aton(host)
                        all_names.add(socket.gethostbyaddr(host)[0])
                    except (socket.error, socket.herror, socket.timeout):
                        continue

        return all_names

    def _get_snakeoil_paths(self):
        # TODO: generate only once
        tmp_dir = os.path.join(self.config.work_dir, "snakeoil")
        le_key = crypto_util.init_save_key(
            key_size=1024, key_dir=tmp_dir, keyname="key.pem")
        key = OpenSSL.crypto.load_privatekey(
            OpenSSL.crypto.FILETYPE_PEM, le_key.pem)
        cert = acme_crypto_util.gen_ss_cert(key, domains=[socket.gethostname()])
        cert_pem = OpenSSL.crypto.dump_certificate(
            OpenSSL.crypto.FILETYPE_PEM, cert)
        cert_file, cert_path = le_util.unique_file(os.path.join(tmp_dir, "cert.pem"))
        with cert_file:
            cert_file.write(cert_pem)
        return cert_path, le_key.file

    def _make_server_ssl(self, vhost):
        """Make a server SSL.

        Make a server SSL based on server_name and filename by adding a
        ``listen IConfig.tls_sni_01_port ssl`` directive to the server block.

        .. todo:: Maybe this should create a new block instead of modifying
            the existing one?

        :param vhost: The vhost to add SSL to.
        :type vhost: :class:`~letsencrypt_nginx.obj.VirtualHost`

        """
        snakeoil_cert, snakeoil_key = self._get_snakeoil_paths()
        ssl_block = [['listen', '{0} ssl'.format(self.config.tls_sni_01_port)],
                     ['ssl_certificate', snakeoil_cert],
                     ['ssl_certificate_key', snakeoil_key],
                     ['include', self.parser.loc["ssl_options"]]]
        self.parser.add_server_directives(
            vhost.filep, vhost.names, ssl_block, replace=False)
        vhost.ssl = True
        vhost.raw.extend(ssl_block)
        vhost.addrs.add(obj.Addr(
            '', str(self.config.tls_sni_01_port), True, False))

    def get_all_certs_keys(self):
        """Find all existing keys, certs from configuration.

        :returns: list of tuples with form [(cert, key, path)]
            cert - str path to certificate file
            key - str path to associated key file
            path - File path to configuration file.
        :rtype: set

        """
        return self.parser.get_all_certs_keys()

    ##################################
    # enhancement methods (IInstaller)
    ##################################
    def supported_enhancements(self):  # pylint: disable=no-self-use
        """Returns currently supported enhancements."""
        return ['redirect']

    def enhance(self, domain, enhancement, options=None):
        """Enhance configuration.

        :param str domain: domain to enhance
        :param str enhancement: enhancement type defined in
            :const:`~letsencrypt.constants.ENHANCEMENTS`
        :param options: options for the enhancement
            See :const:`~letsencrypt.constants.ENHANCEMENTS`
            documentation for appropriate parameter.

        """
        try:
            return self._enhance_func[enhancement](
                self.choose_vhost(domain), options)
        except (KeyError, ValueError):
            raise errors.PluginError(
                "Unsupported enhancement: {0}".format(enhancement))
        except errors.PluginError:
            logger.warn("Failed %s for %s", enhancement, domain)

    def _enable_redirect(self, vhost, unused_options):
        """Redirect all equivalent HTTP traffic to ssl_vhost.

        Add rewrite directive to non https traffic

        .. note:: This function saves the configuration

        :param vhost: Destination of traffic, an ssl enabled vhost
        :type vhost: :class:`~letsencrypt_nginx.obj.VirtualHost`

        :param unused_options: Not currently used
        :type unused_options: Not Available
        """
        redirect_block = [[
            ['if', '($scheme != "https")'],
            [['return', '301 https://$host$request_uri']]
        ]]
        self.parser.add_server_directives(
            vhost.filep, vhost.names, redirect_block, replace=False)
        logger.info("Redirecting all traffic to ssl in %s", vhost.filep)

    ######################################
    # Nginx server management (IInstaller)
    ######################################
    def restart(self):
        """Restarts nginx server.

        :raises .errors.MisconfigurationError: If either the reload fails.

        """
        nginx_restart(self.conf('ctl'), self.nginx_conf)

    def config_test(self):  # pylint: disable=no-self-use
        """Check the configuration of Nginx for errors.

        :raises .errors.MisconfigurationError: If config_test fails

        """
        try:
            le_util.run_script([self.conf('ctl'), "-c", self.nginx_conf, "-t"])
        except errors.SubprocessError as err:
            raise errors.MisconfigurationError(str(err))

    def _verify_setup(self):
        """Verify the setup to ensure safe operating environment.

        Make sure that files/directories are setup with appropriate permissions
        Aim for defensive coding... make sure all input files
        have permissions of root.

        """
        uid = os.geteuid()
        le_util.make_or_verify_dir(
            self.config.work_dir, core_constants.CONFIG_DIRS_MODE, uid)
        le_util.make_or_verify_dir(
            self.config.backup_dir, core_constants.CONFIG_DIRS_MODE, uid)
        le_util.make_or_verify_dir(
            self.config.config_dir, core_constants.CONFIG_DIRS_MODE, uid)

    def get_version(self):
        """Return version of Nginx Server.

        Version is returned as tuple. (ie. 2.4.7 = (2, 4, 7))

        :returns: version
        :rtype: tuple

        :raises .PluginError:
            Unable to find Nginx version or version is unsupported

        """
        try:
            proc = subprocess.Popen(
                [self.conf('ctl'), "-c", self.nginx_conf, "-V"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE)
            text = proc.communicate()[1]  # nginx prints output to stderr
        except (OSError, ValueError) as error:
            logging.debug(error, exc_info=True)
            raise errors.PluginError(
                "Unable to run %s -V" % self.conf('ctl'))

        version_regex = re.compile(r"nginx/([0-9\.]*)", re.IGNORECASE)
        version_matches = version_regex.findall(text)

        sni_regex = re.compile(r"TLS SNI support enabled", re.IGNORECASE)
        sni_matches = sni_regex.findall(text)

        ssl_regex = re.compile(r" --with-http_ssl_module")
        ssl_matches = ssl_regex.findall(text)

        if not version_matches:
            raise errors.PluginError("Unable to find Nginx version")
        if not ssl_matches:
            raise errors.PluginError(
                "Nginx build is missing SSL module (--with-http_ssl_module).")
        if not sni_matches:
            raise errors.PluginError("Nginx build doesn't support SNI")

        nginx_version = tuple([int(i) for i in version_matches[0].split(".")])

        # nginx < 0.8.48 uses machine hostname as default server_name instead of
        # the empty string
        if nginx_version < (0, 8, 48):
            raise errors.NotSupportedError("Nginx version must be 0.8.48+")

        return nginx_version

    def more_info(self):
        """Human-readable string to help understand the module"""
        return (
            "Configures Nginx to authenticate and install HTTPS.{0}"
            "Server root: {root}{0}"
            "Version: {version}".format(
                os.linesep, root=self.parser.loc["root"],
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

        """
        save_files = set(self.parser.parsed.keys())

        # Create Checkpoint
        if temporary:
            self.reverter.add_to_temp_checkpoint(
                save_files, self.save_notes)
        else:
            self.reverter.add_to_checkpoint(save_files,
                                            self.save_notes)

        # Change 'ext' to something else to not override existing conf files
        self.parser.filedump(ext='')
        if title and not temporary:
            self.reverter.finalize_checkpoint(title)

        return True

    def recovery_routine(self):
        """Revert all previously modified files.

        Reverts all modified files that have not been saved as a checkpoint

        """
        self.reverter.recovery_routine()
        self.parser.load()

    def revert_challenge_config(self):
        """Used to cleanup challenge configurations."""
        self.reverter.revert_temporary_config()
        self.parser.load()

    def rollback_checkpoints(self, rollback=1):
        """Rollback saved checkpoints.

        :param int rollback: Number of checkpoints to revert

        """
        self.reverter.rollback_checkpoints(rollback)
        self.parser.load()

    def view_config_changes(self):
        """Show all of the configuration changes that have taken place."""
        self.reverter.view_config_changes()

    ###########################################################################
    # Challenges Section for IAuthenticator
    ###########################################################################
    def get_chall_pref(self, unused_domain):  # pylint: disable=no-self-use
        """Return list of challenge preferences."""
        return [challenges.TLSSNI01]

    # Entry point in main.py for performing challenges
    def perform(self, achalls):
        """Perform the configuration related challenge.

        This function currently assumes all challenges will be fulfilled.
        If this turns out not to be the case in the future. Cleanup and
        outstanding challenges will have to be designed better.

        """
        self._chall_out += len(achalls)
        responses = [None] * len(achalls)
        chall_doer = tls_sni_01.NginxTlsSni01(self)

        for i, achall in enumerate(achalls):
            # Currently also have chall_doer hold associated index of the
            # challenge. This helps to put all of the responses back together
            # when they are all complete.
            chall_doer.add_chall(achall, i)

        sni_response = chall_doer.perform()
        # Must restart in order to activate the challenges.
        # Handled here because we may be able to load up other challenge types
        self.restart()

        # Go through all of the challenges and assign them to the proper place
        # in the responses return value. All responses must be in the same order
        # as the original challenges.
        for i, resp in enumerate(sni_response):
            responses[chall_doer.indices[i]] = resp

        return responses

    # called after challenges are performed
    def cleanup(self, achalls):
        """Revert all challenges."""
        self._chall_out -= len(achalls)

        # If all of the challenges have been finished, clean up everything
        if self._chall_out <= 0:
            self.revert_challenge_config()
            self.restart()


def nginx_restart(nginx_ctl, nginx_conf="/etc/nginx.conf"):
    """Restarts the Nginx Server.

    .. todo:: Nginx restart is fatal if the configuration references
        non-existent SSL cert/key files. Remove references to /etc/letsencrypt
        before restart.

    :param str nginx_ctl: Path to the Nginx binary.

    """
    try:
        proc = subprocess.Popen([nginx_ctl, "-c", nginx_conf, "-s", "reload"],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        stdout, stderr = proc.communicate()

        if proc.returncode != 0:
            # Maybe Nginx isn't running
            nginx_proc = subprocess.Popen([nginx_ctl, "-c", nginx_conf],
                                          stdout=subprocess.PIPE,
                                          stderr=subprocess.PIPE)
            stdout, stderr = nginx_proc.communicate()

            if nginx_proc.returncode != 0:
                # Enter recovery routine...
                raise errors.MisconfigurationError(
                    "nginx restart failed:\n%s\n%s" % (stdout, stderr))

    except (OSError, ValueError):
        raise errors.MisconfigurationError("nginx restart failed")
    # Nginx can take a moment to recognize a newly added TLS SNI servername, so sleep
    # for a second. TODO: Check for expected servername and loop until it
    # appears or return an error if looping too long.
    time.sleep(1)


def temp_install(options_ssl):
    """Temporary install for convenience."""
    # WARNING: THIS IS A POTENTIAL SECURITY VULNERABILITY
    # THIS SHOULD BE HANDLED BY THE PACKAGE MANAGER
    # AND TAKEN OUT BEFORE RELEASE, INSTEAD
    # SHOWING A NICE ERROR MESSAGE ABOUT THE PROBLEM.

    # Check to make sure options-ssl.conf is installed
    if not os.path.isfile(options_ssl):
        shutil.copyfile(constants.MOD_SSL_CONF_SRC, options_ssl)
