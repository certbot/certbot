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
        self._enhance_func = {"redirect": self._enable_redirect}

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
        return ["redirect"]

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

    def _enable_redirect(self, ssl_vhost, unused_options):
        """Redirect all equivalent HTTP traffic to ssl_vhost.

        .. todo:: This enhancement should be rewritten and will
           unfortunately require lots of debugging by hand.

        Adds Redirect directive to the port 80 equivalent of ssl_vhost
        First the function attempts to find the vhost with equivalent
        ip addresses that serves on non-ssl ports
        The function then adds the directive

        .. note:: This function saves the configuration

        :param ssl_vhost: Destination of traffic, an ssl enabled vhost
        :type ssl_vhost:
            :class:`~letsencrypt.client.plugins.nginx.obj.VirtualHost`

        :param unused_options: Not currently used
        :type unused_options: Not Available

        :returns: Success, general_vhost (HTTP vhost)
        :rtype: (bool,
            :class:`~letsencrypt.client.plugins.nginx.obj.VirtualHost`)

        """
        if not mod_loaded("rewrite_module", self.config.nginx_ctl):
            enable_mod("rewrite", self.config.nginx_init_script,
                       self.config.nginx_enmod)

        general_v = self._general_vhost(ssl_vhost)
        if general_v is None:
            # Add virtual_server with redirect
            logging.debug(
                "Did not find http version of ssl virtual host... creating")
            return self._create_redirect_vhost(ssl_vhost)
        else:
            # Check if redirection already exists
            exists, code = self._existing_redirect(general_v)
            if exists:
                if code == 0:
                    logging.debug("Redirect already added")
                    logging.info(
                        "Configuration is already redirecting traffic to HTTPS")
                    return
                else:
                    logging.info("Unknown redirect exists for this vhost")
                    raise errors.LetsEncryptConfiguratorError(
                        "Unknown redirect already exists "
                        "in {}".format(general_v.filep))
            # Add directives to server
            self.parser.add_dir(general_v.path, "RewriteEngine", "On")
            self.parser.add_dir(general_v.path, "RewriteRule",
                                constants.APACHE_REWRITE_HTTPS_ARGS)
            self.save_notes += ("Redirecting host in %s to ssl vhost in %s\n" %
                                (general_v.filep, ssl_vhost.filep))
            self.save()

            logging.info("Redirecting vhost in %s to ssl vhost in %s",
                         general_v.filep, ssl_vhost.filep)

    def _existing_redirect(self, vhost):
        """Checks to see if existing redirect is in place.

        Checks to see if virtualhost already contains a rewrite or redirect
        returns boolean, integer
        The boolean indicates whether the redirection exists...
        The integer has the following code:
        0 - Existing letsencrypt https rewrite rule is appropriate and in place
        1 - Virtual host contains a Redirect directive
        2 - Virtual host contains an unknown RewriteRule

        -1 is also returned in case of no redirection/rewrite directives

        :param vhost: vhost to check
        :type vhost: :class:`~letsencrypt.client.plugins.nginx.obj.VirtualHost`

        :returns: Success, code value... see documentation
        :rtype: bool, int

        """
        rewrite_path = self.parser.find_dir(
            parser.case_i("RewriteRule"), None, vhost.path)
        redirect_path = self.parser.find_dir(
            parser.case_i("Redirect"), None, vhost.path)

        if redirect_path:
            # "Existing Redirect directive for virtualhost"
            return True, 1
        if not rewrite_path:
            # "No existing redirection for virtualhost"
            return False, -1
        if len(rewrite_path) == len(constants.APACHE_REWRITE_HTTPS_ARGS):
            for idx, match in enumerate(rewrite_path):
                if (self.aug.get(match) !=
                        constants.APACHE_REWRITE_HTTPS_ARGS[idx]):
                    # Not a letsencrypt https rewrite
                    return True, 2
            # Existing letsencrypt https rewrite rule is in place
            return True, 0
        # Rewrite path exists but is not a letsencrypt https rule
        return True, 2

    def _create_redirect_vhost(self, ssl_vhost):
        """Creates an http_vhost specifically to redirect for the ssl_vhost.

        :param ssl_vhost: ssl vhost
        :type ssl_vhost:
            :class:`~letsencrypt.client.plugins.nginx.obj.VirtualHost`

        :returns: tuple of the form
            (`success`,
            :class:`~letsencrypt.client.plugins.nginx.obj.VirtualHost`)
        :rtype: tuple

        """
        # Consider changing this to a dictionary check
        # Make sure adding the vhost will be safe
        conflict, host_or_addrs = self._conflicting_host(ssl_vhost)
        if conflict:
            raise errors.LetsEncryptConfiguratorError(
                "Unable to create a redirection vhost "
                "- {}".format(host_or_addrs))

        redirect_addrs = host_or_addrs

        # get servernames and serveraliases
        serveralias = ""
        servername = ""
        size_n = len(ssl_vhost.names)
        if size_n > 0:
            servername = "ServerName " + ssl_vhost.names[0]
            if size_n > 1:
                serveralias = " ".join(ssl_vhost.names[1:size_n])
                serveralias = "ServerAlias " + serveralias
        redirect_file = ("<VirtualHost" + redirect_addrs + ">\n"
                         "%s \n"
                         "%s \n"
                         "ServerSignature Off\n"
                         "\n"
                         "RewriteEngine On\n"
                         "RewriteRule %s\n"
                         "\n"
                         "ErrorLog /var/log/nginx2/redirect.error.log\n"
                         "LogLevel warn\n"
                         "</VirtualHost>\n"
                         % (servername, serveralias,
                            " ".join(constants.APACHE_REWRITE_HTTPS_ARGS)))

        # Write out the file
        # This is the default name
        redirect_filename = "le-redirect.conf"

        # See if a more appropriate name can be applied
        if len(ssl_vhost.names) > 0:
            # Sanity check...
            # make sure servername doesn't exceed filename length restriction
            if ssl_vhost.names[0] < (255-23):
                redirect_filename = "le-redirect-%s.conf" % ssl_vhost.names[0]

        redirect_filepath = os.path.join(
            self.parser.root, "sites-available", redirect_filename)

        # Register the new file that will be created
        # Note: always register the creation before writing to ensure file will
        # be removed in case of unexpected program exit
        self.reverter.register_file_creation(False, redirect_filepath)

        # Write out file
        with open(redirect_filepath, "w") as redirect_fd:
            redirect_fd.write(redirect_file)
        logging.info("Created redirect file: %s", redirect_filename)

        self.aug.load()
        # Make a new vhost data structure and add it to the lists
        new_vhost = self._create_vhost(parser.get_aug_path(redirect_filepath))
        self.vhosts.append(new_vhost)

        # Finally create documentation for the change
        self.save_notes += ("Created a port 80 vhost, %s, for redirection to "
                            "ssl vhost %s\n" %
                            (new_vhost.filep, ssl_vhost.filep))

    def _conflicting_host(self, ssl_vhost):
        """Checks for conflicting HTTP vhost for ssl_vhost.

        Checks for a conflicting host, such that a new port 80 host could not
        be created without ruining the nginx config
        Used with redirection

        returns: conflict, host_or_addrs - boolean
        if conflict: returns conflicting vhost
        if not conflict: returns space separated list of new host addrs

        :param ssl_vhost: SSL Vhost to check for possible port 80 redirection
        :type ssl_vhost:
            :class:`~letsencrypt.client.plugins.nginx.obj.VirtualHost`

        :returns: TODO
        :rtype: TODO

        """
        # Consider changing this to a dictionary check
        redirect_addrs = ""
        for ssl_a in ssl_vhost.addrs:
            # Add space on each new addr, combine "VirtualHost"+redirect_addrs
            redirect_addrs = redirect_addrs + " "
            ssl_a_vhttp = ssl_a.get_addr_obj("80")
            # Search for a conflicting host...
            for vhost in self.vhosts:
                if vhost.enabled:
                    if (ssl_a_vhttp in vhost.addrs or
                            ssl_a.get_addr_obj("") in vhost.addrs or
                            ssl_a.get_addr_obj("*") in vhost.addrs):
                        # We have found a conflicting host... just return
                        return True, vhost

            redirect_addrs = redirect_addrs + ssl_a_vhttp

        return False, redirect_addrs

    def _general_vhost(self, ssl_vhost):
        """Find appropriate HTTP vhost for ssl_vhost.

        Function needs to be thoroughly tested and perhaps improved
        Will not do well with malformed configurations
        Consider changing this into a dict check

        :param ssl_vhost: ssl vhost to check
        :type ssl_vhost:
            :class:`~letsencrypt.client.plugins.nginx.obj.VirtualHost`

        :returns: HTTP vhost or None if unsuccessful
        :rtype: :class:`~letsencrypt.client.plugins.nginx.obj.VirtualHost`
            or None

        """
        # _default_:443 check
        # Instead... should look for vhost of the form *:80
        # Should we prompt the user?
        ssl_addrs = ssl_vhost.addrs
        if ssl_addrs == obj.Addr.fromstring("_default_:443"):
            ssl_addrs = [obj.Addr.fromstring("*:443")]

        for vhost in self.vhosts:
            found = 0
            # Not the same vhost, and same number of addresses
            if vhost != ssl_vhost and len(vhost.addrs) == len(ssl_vhost.addrs):
                # Find each address in ssl_host in test_host
                for ssl_a in ssl_addrs:
                    for test_a in vhost.addrs:
                        if test_a.get_addr() == ssl_a.get_addr():
                            # Check if found...
                            if (test_a.get_port() == "80" or
                                    test_a.get_port() == "" or
                                    test_a.get_port() == "*"):
                                found += 1
                                break
                # Check to make sure all addresses were found
                # and names are equal
                if (found == len(ssl_vhost.addrs) and
                        vhost.names == ssl_vhost.names):
                    return vhost
        return None

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
        return nginx_restart(self.config.nginx_init_script)

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


def enable_mod(mod_name, nginx_init_script, nginx_enmod):
    """Enables module in Nginx.

    Both enables and restarts Nginx so module is active.

    :param str mod_name: Name of the module to enable.
    :param str nginx_init_script: Path to the Nginx init script.
    :param str nginx_enmod: Path to the Nginx a2enmod script.

    """
    try:
        # Use check_output so the command will finish before reloading
        # TODO: a2enmod is debian specific...
        subprocess.check_call(["sudo", nginx_enmod, mod_name],  # TODO: sudo?
                              stdout=open("/dev/null", "w"),
                              stderr=open("/dev/null", "w"))
        nginx_restart(nginx_init_script)
    except (OSError, subprocess.CalledProcessError) as err:
        logging.error("Error enabling mod_%s", mod_name)
        logging.error("Exception: %s", err)
        sys.exit(1)


def mod_loaded(module, nginx_ctl):
    """Checks to see if mod_ssl is loaded

    Uses ``nginx_ctl`` to get loaded module list. This also effectively
    serves as a config_test.

    :param str nginx_ctl: Path to nginx2ctl binary.

    :returns: If ssl_module is included and active in Nginx
    :rtype: bool

    """
    try:
        proc = subprocess.Popen(
            [nginx_ctl, "-M"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)
        stdout, stderr = proc.communicate()

    except (OSError, ValueError):
        logging.error(
            "Error accessing %s for loaded modules!", nginx_ctl)
        raise errors.LetsEncryptConfiguratorError(
            "Error accessing loaded modules")
    # Small errors that do not impede
    if proc.returncode != 0:
        logging.warn("Error in checking loaded module list: %s", stderr)
        raise errors.LetsEncryptMisconfigurationError(
            "Nginx is unable to check whether or not the module is "
            "loaded because Nginx is misconfigured.")

    if module in stdout:
        return True
    return False


def nginx_restart(nginx_init_script):
    """Restarts the Nginx Server.

    :param str nginx_init_script: Path to the Nginx init script.

    .. todo:: Try to use reload instead. (This caused timing problems before)

    .. todo:: On failure, this should be a recovery_routine call with another
       restart.  This will confuse and inhibit developers from testing code
       though.  This change should happen after
       the NginxConfigurator has been thoroughly tested.  The function will
       need to be moved into the class again.  Perhaps
       this version can live on... for testing purposes.

    """
    try:
        proc = subprocess.Popen([nginx_init_script, "restart"],
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
