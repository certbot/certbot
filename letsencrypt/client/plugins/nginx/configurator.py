"""Nginx Configuration"""
import logging
import os
import re
import shutil
import socket
import subprocess
import sys

import zope.interface

from letsencrypt.acme import challenges

from letsencrypt.client import achallenges
from letsencrypt.client import constants
from letsencrypt.client import errors
from letsencrypt.client import interfaces
from letsencrypt.client import le_util
from letsencrypt.client import reverter

from letsencrypt.client.plugins.nginx import dvsni
from letsencrypt.client.plugins.nginx import obj
from letsencrypt.client.plugins.nginx import parser


class NginxConfigurator(object):
    # pylint: disable=too-many-instance-attributes,too-many-public-methods
    """Nginx configurator.

    .. todo:: Add proper support for comments in the config

    :ivar config: Configuration.
    :type config: :class:`~letsencrypt.client.interfaces.IConfig`

    :ivar parser: Handles low level parsing
    :type parser: :class:`~letsencrypt.client.plugins.nginx.parser`

    :ivar tup version: version of Nginx
    :ivar list vhosts: All vhosts found in the configuration
        (:class:`list` of
        :class:`~letsencrypt.client.plugins.nginx.obj.VirtualHost`)

    :ivar dict assoc: Mapping between domains and vhosts

    """
    zope.interface.implements(interfaces.IAuthenticator, interfaces.IInstaller)

    description = "Nginx Web Server"

    def __init__(self, config, version=None):
        """Initialize an Nginx Configurator.

        :param tup version: version of Nginx as a tuple (2, 4, 7)
            (used mostly for unittesting)

        """
        self.config = config
        self.save_notes = ""

        # Verify that all directories and files exist with proper permissions
        if os.geteuid() == 0:
            self.verify_setup()

        # Add name_server association dict
        self.assoc = dict()
        # Add number of outstanding challenges
        self._chall_out = 0

        # These will be set in the prepare function
        self.parser = None
        self.version = version
        self.vhosts = None
        self._enhance_func = {}  # TODO: Support at least redirects

        # Set up reverter
        self.reverter = reverter.Reverter(config)
        self.reverter.recovery_routine()

    def prepare(self):
        """Prepare the authenticator/installer."""
        self.parser = parser.NginxParser(
            self.config.nginx_server_root,
            self.config.nginx_mod_ssl_conf)

        # Set Version
        if self.version is None:
            self.version = self.get_version()

        # Get all of the available vhosts
        self.vhosts = self.get_virtual_hosts()

        temp_install(self.config.nginx_mod_ssl_conf)

    def deploy_cert(self, domain, cert, key, cert_chain=None):
        """Deploys certificate to specified virtual host.

        Currently tries to find the last directives to deploy the cert in
        the VHost associated with the given domain. If it can't find the
        directives, it searches the "included" confs. The function verifies that
        it has located the three directives and finally modifies them to point
        to the correct destination. After the certificate is installed, the
        VirtualHost is enabled if it isn't already.

        .. todo:: Make sure last directive is changed

        .. todo:: Might be nice to remove chain directive if none exists
                  This shouldn't happen within letsencrypt though

        :param str domain: domain to deploy certificate
        :param str cert: certificate filename
        :param str key: private key filename
        :param str cert_chain: certificate chain filename

        """
        vhost = self.choose_vhost(domain)
        path = {}

        path["cert_file"] = self.parser.find_dir(parser.case_i(
            "SSLCertificateFile"), None, vhost.path)
        path["cert_key"] = self.parser.find_dir(parser.case_i(
            "SSLCertificateKeyFile"), None, vhost.path)

        # Only include if a certificate chain is specified
        if cert_chain is not None:
            path["cert_chain"] = self.parser.find_dir(
                parser.case_i("SSLCertificateChainFile"), None, vhost.path)

        if len(path["cert_file"]) == 0 or len(path["cert_key"]) == 0:
            # Throw some can't find all of the directives error"
            logging.warn(
                "Cannot find a cert or key directive in %s", vhost.path)
            logging.warn("VirtualHost was not modified")
            # Presumably break here so that the virtualhost is not modified
            return False

        logging.info("Deploying Certificate to VirtualHost %s", vhost.filep)

        self.aug.set(path["cert_file"][0], cert)
        self.aug.set(path["cert_key"][0], key)
        if cert_chain is not None:
            if len(path["cert_chain"]) == 0:
                self.parser.add_dir(
                    vhost.path, "SSLCertificateChainFile", cert_chain)
            else:
                self.aug.set(path["cert_chain"][0], cert_chain)

        self.save_notes += ("Changed vhost at %s with addresses of %s\n" %
                            (vhost.filep,
                             ", ".join(str(addr) for addr in vhost.addrs)))
        self.save_notes += "\tSSLCertificateFile %s\n" % cert
        self.save_notes += "\tSSLCertificateKeyFile %s\n" % key
        if cert_chain:
            self.save_notes += "\tSSLCertificateChainFile %s\n" % cert_chain

        # Make sure vhost is enabled
        if not vhost.enabled:
            self.enable_site(vhost)

    def choose_vhost(self, target_name):
        """Chooses a virtual host based on the given domain name.

        .. todo:: This should maybe return list if no obvious answer
            is presented.

        :param str target_name: domain name

        :returns: ssl vhost associated with name
        :rtype: :class:`~letsencrypt.client.plugins.nginx.obj.VirtualHost`

        """
        # Allows for domain names to be associated with a virtual host
        # Client isn't using create_dn_server_assoc(self, dn, vh) yet
        if target_name in self.assoc:
            return self.assoc[target_name]
        # Check for servernames/aliases for ssl hosts
        for vhost in self.vhosts:
            if vhost.ssl and target_name in vhost.names:
                self.assoc[target_name] = vhost
                return vhost
        # Checking for domain name in vhost address
        # This technique is not recommended by Nginx but is technically valid
        target_addr = obj.Addr((target_name, "443"))
        for vhost in self.vhosts:
            if target_addr in vhost.addrs:
                self.assoc[target_name] = vhost
                return vhost

        # Check for non ssl vhosts with servernames/aliases == "name"
        for vhost in self.vhosts:
            if not vhost.ssl and target_name in vhost.names:
                vhost = self.make_vhost_ssl(vhost)
                self.assoc[target_name] = vhost
                return vhost

        # No matches, search for the default
        for vhost in self.vhosts:
            if "_default_:443" in vhost.addrs:
                return vhost
        return None

    def create_dn_server_assoc(self, domain, vhost):
        """Create an association between a domain name and virtual host.

        Helps to choose an appropriate vhost

        :param str domain: domain name to associate

        :param vhost: virtual host to associate with domain
        :type vhost: :class:`~letsencrypt.client.plugins.nginx.obj.VirtualHost`

        """
        self.assoc[domain] = vhost

    def get_all_names(self):
        """Returns all names found in the Nginx Configuration.

        :returns: All ServerNames, ServerAliases, and reverse DNS entries for
                  virtual host addresses
        :rtype: set

        """
        all_names = set()

        # Kept in same function to avoid multiple compilations of the regex
        priv_ip_regex = (r"(^127\.0\.0\.1)|(^10\.)|(^172\.1[6-9]\.)|"
                         r"(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^192\.168\.)")
        private_ips = re.compile(priv_ip_regex)

        for vhost in self.vhosts:
            all_names.update(vhost.names)
            for addr in vhost.addrs:
                # If it isn't a private IP, do a reverse DNS lookup
                if not private_ips.match(addr.get_addr()):
                    try:
                        socket.inet_aton(addr.get_addr())
                        all_names.add(socket.gethostbyaddr(addr.get_addr())[0])
                    except (socket.error, socket.herror, socket.timeout):
                        continue

        return all_names

    # TODO: make "sites-available" a configurable directory
    def get_virtual_hosts(self):
        """Returns list of virtual hosts found in the Nginx configuration.

        :returns: List of
            :class:`~letsencrypt.client.plugins.nginx.obj.VirtualHost` objects
            found in configuration
        :rtype: list

        """
        # Search sites-available/, conf.d/, nginx.conf for possible vhosts
        paths = self.parser.get_conf_files()
        vhs = []

        for path in paths:
            vhs.append(self.parser.get_vhosts(path))

        return vhs

    def add_name_vhost(self, addr):
        """Adds NameVirtualHost directive for given address.

        :param str addr: Address that will be added as NameVirtualHost directive

        """
        path = self.parser.add_dir_to_ifmodssl(
            parser.get_aug_path(
                self.parser.loc["name"]), "NameVirtualHost", str(addr))

        self.save_notes += "Setting %s to be NameBasedVirtualHost\n" % addr
        self.save_notes += "\tDirective added to %s\n" % path

    def make_vhost_ssl(self, nonssl_vhost):  # pylint: disable=too-many-locals
        """Makes an ssl_vhost version of a nonssl_vhost.

        Duplicates vhost and adds default ssl options
        New vhost will reside as (nonssl_vhost.path) + ``IConfig.le_vhost_ext``

        .. note:: This function saves the configuration

        :param nonssl_vhost: Valid VH that doesn't have SSLEngine on
        :type nonssl_vhost:
            :class:`~letsencrypt.client.plugins.nginx.obj.VirtualHost`

        :returns: SSL vhost
        :rtype: :class:`~letsencrypt.client.plugins.nginx.obj.VirtualHost`

        """
        avail_fp = nonssl_vhost.filep
        # Get filepath of new ssl_vhost
        if avail_fp.endswith(".conf"):
            ssl_fp = avail_fp[:-(len(".conf"))] + self.config.le_vhost_ext
        else:
            ssl_fp = avail_fp + self.config.le_vhost_ext

        # First register the creation so that it is properly removed if
        # configuration is rolled back
        self.reverter.register_file_creation(False, ssl_fp)

        try:
            with open(avail_fp, "r") as orig_file:
                with open(ssl_fp, "w") as new_file:
                    new_file.write("<IfModule mod_ssl.c>\n")
                    for line in orig_file:
                        new_file.write(line)
                    new_file.write("</IfModule>\n")
        except IOError:
            logging.fatal("Error writing/reading to file in make_vhost_ssl")
            sys.exit(49)

        self.aug.load()

        ssl_addrs = set()

        # change address to address:443
        addr_match = "/files%s//* [label()=~regexp('%s')]/arg"
        ssl_addr_p = self.aug.match(
            addr_match % (ssl_fp, parser.case_i("VirtualHost")))

        for addr in ssl_addr_p:
            old_addr = obj.Addr.fromstring(
                str(self.aug.get(addr)))
            ssl_addr = old_addr.get_addr_obj("443")
            self.aug.set(addr, str(ssl_addr))
            ssl_addrs.add(ssl_addr)

        # Add directives
        vh_p = self.aug.match("/files%s//* [label()=~regexp('%s')]" %
                              (ssl_fp, parser.case_i("VirtualHost")))
        if len(vh_p) != 1:
            logging.error("Error: should only be one vhost in %s", avail_fp)
            sys.exit(1)

        self.parser.add_dir(vh_p[0], "SSLCertificateFile",
                            "/etc/ssl/certs/ssl-cert-snakeoil.pem")
        self.parser.add_dir(vh_p[0], "SSLCertificateKeyFile",
                            "/etc/ssl/private/ssl-cert-snakeoil.key")
        self.parser.add_dir(vh_p[0], "Include", self.parser.loc["ssl_options"])

        # Log actions and create save notes
        logging.info("Created an SSL vhost at %s", ssl_fp)
        self.save_notes += "Created ssl vhost at %s\n" % ssl_fp
        self.save()

        # We know the length is one because of the assertion above
        ssl_vhost = self._create_vhost(vh_p[0])
        self.vhosts.append(ssl_vhost)

        return ssl_vhost

    def supported_enhancements(self):  # pylint: disable=no-self-use
        """Returns currently supported enhancements."""
        return []

    def enhance(self, domain, enhancement, options=None):
        """Enhance configuration.

        :param str domain: domain to enhance
        :param str enhancement: enhancement type defined in
            :const:`~letsencrypt.client.constants.ENHANCEMENTS`
        :param options: options for the enhancement
            See :const:`~letsencrypt.client.constants.ENHANCEMENTS`
            documentation for appropriate parameter.

        """
        try:
            return self._enhance_func[enhancement](
                self.choose_vhost(domain), options)
        except ValueError:
            raise errors.LetsEncryptConfiguratorError(
                "Unsupported enhancement: {}".format(enhancement))
        except errors.LetsEncryptConfiguratorError:
            logging.warn("Failed %s for %s", enhancement, domain)

    def get_all_certs_keys(self):
        """Find all existing keys, certs from configuration.

        Retrieve all certs and keys set in VirtualHosts on the Nginx server

        :returns: list of tuples with form [(cert, key, path)]
            cert - str path to certificate file
            key - str path to associated key file
            path - File path to configuration file.
        :rtype: list

        """
        c_k = set()

        for vhost in self.vhosts:
            if vhost.ssl:
                cert_path = self.parser.find_dir(
                    parser.case_i("SSLCertificateFile"), None, vhost.path)
                key_path = self.parser.find_dir(
                    parser.case_i("SSLCertificateKeyFile"), None, vhost.path)

                # Can be removed once find directive can return ordered results
                if len(cert_path) != 1 or len(key_path) != 1:
                    logging.error("Too many cert or key directives in vhost %s",
                                  vhost.filep)
                    sys.exit(40)

                cert = os.path.abspath(self.aug.get(cert_path[0]))
                key = os.path.abspath(self.aug.get(key_path[0]))
                c_k.add((cert, key, get_file_path(cert_path[0])))

        return c_k

    def is_site_enabled(self, avail_fp):
        """Checks to see if the given site is enabled.

        .. todo:: fix hardcoded sites-enabled, check os.path.samefile

        :param str avail_fp: Complete file path of available site

        :returns: Success
        :rtype: bool

        """
        enabled_dir = os.path.join(self.parser.root, "sites-enabled")
        for entry in os.listdir(enabled_dir):
            if os.path.realpath(os.path.join(enabled_dir, entry)) == avail_fp:
                return True

        return False

    def enable_site(self, vhost):
        """Enables an available site, Nginx restart required.

        .. todo:: This function should number subdomains before the domain vhost

        .. todo:: Make sure link is not broken...

        :param vhost: vhost to enable
        :type vhost: :class:`~letsencrypt.client.plugins.nginx.obj.VirtualHost`

        :returns: Success
        :rtype: bool

        """
        if self.is_site_enabled(vhost.filep):
            return True

        if "/sites-available/" in vhost.filep:
            enabled_path = ("%s/sites-enabled/%s" %
                            (self.parser.root, os.path.basename(vhost.filep)))
            self.reverter.register_file_creation(False, enabled_path)
            os.symlink(vhost.filep, enabled_path)
            vhost.enabled = True
            logging.info("Enabling available site: %s", vhost.filep)
            self.save_notes += "Enabled site %s\n" % vhost.filep
            return True
        return False

    def restart(self):
        """Restarts nginx server.

        :returns: Success
        :rtype: bool

        """
        return nginx_restart(self.config.nginx_ctl)

    def config_test(self):  # pylint: disable=no-self-use
        """Check the configuration of Nginx for errors.

        :returns: Success
        :rtype: bool

        """
        try:
            proc = subprocess.Popen(
                [self.config.nginx_ctl, "-t"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE)
            stdout, stderr = proc.communicate()
        except (OSError, ValueError):
            logging.fatal("Unable to run nginx config test")
            sys.exit(1)

        if proc.returncode != 0:
            # Enter recovery routine...
            logging.error("Config test failed")
            logging.error(stdout)
            logging.error(stderr)
            return False

        return True

    def verify_setup(self):
        """Verify the setup to ensure safe operating environment.

        Make sure that files/directories are setup with appropriate permissions
        Aim for defensive coding... make sure all input files
        have permissions of root

        """
        uid = os.geteuid()
        le_util.make_or_verify_dir(self.config.config_dir, 0o755, uid)
        le_util.make_or_verify_dir(self.config.work_dir, 0o755, uid)
        le_util.make_or_verify_dir(self.config.backup_dir, 0o755, uid)

    def get_version(self):
        """Return version of Nginx Server.

        Version is returned as tuple. (ie. 2.4.7 = (2, 4, 7))

        :returns: version
        :rtype: tuple

        :raises errors.LetsEncryptConfiguratorError:
            Unable to find Nginx version or version is unsupported

        """
        try:
            proc = subprocess.Popen(
                [self.config.nginx_ctl, "-V"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE)
            text = proc.communicate()[1]  # nginx prints output to stderr
        except (OSError, ValueError):
            raise errors.LetsEncryptConfiguratorError(
                "Unable to run %s -V" % self.config.nginx_ctl)

        version_regex = re.compile(r"nginx/([0-9\.]*)", re.IGNORECASE)
        version_matches = version_regex.findall(text)

        sni_regex = re.compile(r"TLS SNI support enabled", re.IGNORECASE)
        sni_matches = sni_regex.findall(text)

        if len(version_matches) == 0:
            raise errors.LetsEncryptConfiguratorError(
                "Unable to find Nginx version")
        if len(sni_matches) == 0:
            raise errors.LetsEncryptConfiguratorError(
                "Nginx build doesn't support SNI")

        nginx_version = tuple([int(i) for i in version_matches[0].split(".")])

        # nginx <= 0.7.14 has an incompatible SSL configuration format
        if (nginx_version[0] == 0 and
            (nginx_version[1] < 7 or
             (nginx_version[1] == 7 and nginx_version[2] < 15))):
            raise errors.LetsEncryptConfiguratorError(
                "Nginx version not supported")

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

    # Wrapper functions for Reverter class
    def save(self, title=None, temporary=False):
        """Saves all changes to the configuration files.

        Working changes are saved in *.conf.le files. This overrides the .conf
        file with the .conf.le file contents.

        :param str title: The title of the save. If a title is given, the
            configuration will be saved as a new checkpoint and put in a
            timestamped directory.

        :param bool temporary: Indicates whether the changes made will
            be quickly reversed in the future (ie. challenges)

        """
        if len(self.save_files) > 0:
            # Create Checkpoint
            if temporary:
                self.reverter.add_to_temp_checkpoint(
                    self.save_files, self.save_notes)
            else:
                self.reverter.add_to_checkpoint(self.save_files,
                                                self.save_notes)
            # Override the original files with their working copies
            for f in self.save_files:
                tmpfile = f + '.le'
                if (os.path.isfile(tmpfile)):
                    os.rename(f + '.le', f)
                else:
                    logging.warn("Expected file %s to exist", tmpfile)

        if title and not temporary:
            self.reverter.finalize_checkpoint(title)

        return True

    def recovery_routine(self):
        """Revert all previously modified files.

        Reverts all modified files that have not been saved as a checkpoint

        """
        self.reverter.recovery_routine()

    def revert_challenge_config(self):
        """Used to cleanup challenge configurations."""
        self.reverter.revert_temporary_config()

    def rollback_checkpoints(self, rollback=1):
        """Rollback saved checkpoints.

        :param int rollback: Number of checkpoints to revert

        """
        self.reverter.rollback_checkpoints(rollback)

    def view_config_changes(self):
        """Show all of the configuration changes that have taken place."""
        self.reverter.view_config_changes()

    ###########################################################################
    # Challenges Section
    ###########################################################################
    def get_chall_pref(self, unused_domain):  # pylint: disable=no-self-use
        """Return list of challenge preferences."""
        return [challenges.DVSNI]

    def perform(self, achalls):
        """Perform the configuration related challenge.

        This function currently assumes all challenges will be fulfilled.
        If this turns out not to be the case in the future. Cleanup and
        outstanding challenges will have to be designed better.

        """
        self._chall_out += len(achalls)
        responses = [None] * len(achalls)
        nginx_dvsni = dvsni.NginxDvsni(self)

        for i, achall in enumerate(achalls):
            if isinstance(achall, achallenges.DVSNI):
                # Currently also have dvsni hold associated index
                # of the challenge. This helps to put all of the responses back
                # together when they are all complete.
                nginx_dvsni.add_chall(achall, i)

        sni_response = nginx_dvsni.perform()
        # Must restart in order to activate the challenges.
        # Handled here because we may be able to load up other challenge types
        self.restart()

        # Go through all of the challenges and assign them to the proper place
        # in the responses return value. All responses must be in the same order
        # as the original challenges.
        for i, resp in enumerate(sni_response):
            responses[nginx_dvsni.indices[i]] = resp

        return responses

    def cleanup(self, achalls):
        """Revert all challenges."""
        self._chall_out -= len(achalls)

        # If all of the challenges have been finished, clean up everything
        if self._chall_out <= 0:
            self.revert_challenge_config()
            self.restart()


def nginx_restart(nginx_ctl):
    """Restarts the Nginx Server.

    :param str nginx_ctl: Path to the Nginx binary.

    """
    try:
        proc = subprocess.Popen([nginx_ctl, "-s", "reload"],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        stdout, stderr = proc.communicate()

        if proc.returncode != 0:
            # Enter recovery routine...
            logging.error("Nginx Restart Failed!")
            logging.error(stdout)
            logging.error(stderr)
            return False

    except (OSError, ValueError):
        logging.fatal(
            "Nginx Restart Failed - Please Check the Configuration")
        sys.exit(1)

    return True


def get_file_path(vhost_path):
    """Get file path from augeas_vhost_path.

    Takes in Augeas path and returns the file name

    :param str vhost_path: Augeas virtual host path

    :returns: filename of vhost
    :rtype: str

    """
    # Strip off /files
    avail_fp = vhost_path[6:]
    # This can be optimized...
    while True:
        # Cast both to lowercase to be case insensitive
        find_if = avail_fp.lower().find("/ifmodule")
        if find_if != -1:
            avail_fp = avail_fp[:find_if]
            continue
        find_vh = avail_fp.lower().find("/virtualhost")
        if find_vh != -1:
            avail_fp = avail_fp[:find_vh]
            continue
        break
    return avail_fp


def temp_install(options_ssl):
    """Temporary install for convenience."""
    # WARNING: THIS IS A POTENTIAL SECURITY VULNERABILITY
    # THIS SHOULD BE HANDLED BY THE PACKAGE MANAGER
    # AND TAKEN OUT BEFORE RELEASE, INSTEAD
    # SHOWING A NICE ERROR MESSAGE ABOUT THE PROBLEM.

    # Check to make sure options-ssl.conf is installed
    if not os.path.isfile(options_ssl):
        shutil.copyfile(constants.NGINX_MOD_SSL_CONF, options_ssl)
