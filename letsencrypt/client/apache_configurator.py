"""Apache Configuration based off of Augeas Configurator."""
import logging
import os
import pkg_resources
import re
import shutil
import socket
import subprocess
import sys

import zope.interface

from letsencrypt.client import augeas_configurator
from letsencrypt.client import challenge_util
from letsencrypt.client import CONFIG
from letsencrypt.client import errors
from letsencrypt.client import interfaces
from letsencrypt.client import le_util

from letsencrypt.client.apache import obj
from letsencrypt.client.apache import parser

# TODO: Augeas sections ie. <VirtualHost>, <IfModule> beginning and closing
# tags need to be the same case, otherwise Augeas doesn't recognize them.
# This is not able to be completely remedied by regular expressions because
# Augeas views <VirtualHost> </Virtualhost> as an error. This will just
# require another check_parsing_errors() after all files are included...
# (after a find_directive search is executed currently). It can be a one
# time check however because all of LE's transactions will ensure
# only properly formed sections are added.

# Note: This protocol works for filenames with spaces in it, the sites are
# properly set up and directives are changed appropriately, but Apache won't
# recognize names in sites-enabled that have spaces. These are not added to the
# Apache configuration. It may be wise to warn the user if they are trying
# to use vhost filenames that contain spaces and offer to change ' ' to '_'

# Note: FILEPATHS and changes to files are transactional.  They are copied
# over before the updates are made to the existing files. NEW_FILES is
# transactional due to the use of register_file_creation()


class ApacheConfigurator(augeas_configurator.AugeasConfigurator):
    """Apache configurator.

    State of Configurator: This code has been tested under Ubuntu 12.04
    Apache 2.2 and this code works for Ubuntu 14.04 Apache 2.4. Further
    notes below.

    This class was originally developed for Apache 2.2 and has not seen a
    an overhaul to include proper setup of new Apache configurations.
    I have implemented most of the changes... the missing ones are
    mod_ssl.c vs ssl_mod, and I need to account for configuration variables.
    That being said, this class can still adequately configure most typical
    Apache 2.4 servers as the deprecated NameVirtualHost has no effect
    and the typical directories are parsed by the Augeas configuration
    parser automatically.

    .. todo:: Add support for config file variables Define rootDir /var/www/
    .. todo:: Add proper support for module configuration

    The API of this class will change in the coming weeks as the exact
    needs of client's are clarified with the new and developing protocol.

    :ivar str server_root: Path to Apache root directory
    :ivar dict location: Path to various files associated
        with the configuration
    :ivar float version: version of Apache
    :ivar list vhosts: All vhosts found in the configuration
        (:class:`list` of :class:`letsencrypt.client.apache.obj.VH`)

    :ivar dict assoc: Mapping between domains and vhosts

    """
    zope.interface.implements(interfaces.IAuthenticator, interfaces.IInstaller)

    def __init__(self, server_root=CONFIG.SERVER_ROOT, direc=None,
                 ssl_options=CONFIG.OPTIONS_SSL_CONF, version=None):
        """Initialize an Apache Configurator.

        :param str server_root: the apache server root directory
        :param dict direc: locations of various config directories
            (used mostly for unittesting)
        :param str ssl_options: path of options-ssl.conf
            (used mostly for unittesting)
        :param tup version: version of Apache as a tuple (2, 4, 7)
            (used mostly for unittesting)

        """
        if direc is None:
            direc = {"backup": CONFIG.BACKUP_DIR,
                     "temp": CONFIG.TEMP_CHECKPOINT_DIR,
                     "progress": CONFIG.IN_PROGRESS_DIR,
                     "config": CONFIG.CONFIG_DIR,
                     "work": CONFIG.WORK_DIR}

        super(ApacheConfigurator, self).__init__(direc)

        # See if any temporary changes need to be recovered
        # This needs to occur before VH objects are setup...
        # because this will change the underlying configuration and potential
        # vhosts
        self.recovery_routine()

        # Verify that all directories and files exist with proper permissions
        if os.geteuid() == 0:
            self.verify_setup()

        self.parser = parser.ApacheParser(self.aug, server_root, ssl_options)
        # Check for errors in parsing files with Augeas
        self.check_parsing_errors("httpd.aug")

        # Set Version
        self.version = self.get_version() if version is None else version

        # Get all of the available vhosts
        self.vhosts = self.get_virtual_hosts()
        # Add name_server association dict
        self.assoc = dict()

        # Enable mod_ssl if it isn't already enabled
        # This is Let's Encrypt... we enable mod_ssl on initialization :)
        # TODO: attempt to make the check faster... this enable should
        #       be asynchronous as it shouldn't be that time sensitive
        #       on initialization
        self._prepare_server_https()

        # Note: initialization doesn't check to see if the config is correct
        # by Apache's standards. This should be done by the client (client.py)
        # if it is desired. There may be instances where correct configuration
        # isn't required on startup.

    def deploy_cert(self, vhost, cert, key, cert_chain=None):
        """Deploys certificate to specified virtual host.

        Currently tries to find the last directives to deploy the cert in
        the given virtualhost. If it can't find the directives, it searches
        the "included" confs. The function verifies that it has located
        the three directives and finally modifies them to point to the correct
        destination

        .. todo:: Make sure last directive is changed

        .. todo:: Might be nice to remove chain directive if none exists
                  This shouldn't happen within letsencrypt though

        :param vhost: ssl vhost to deploy certificate
        :type vhost: :class:`letsencrypt.client.apache.obj.VH`

        :param str cert: certificate filename
        :param str key: private key filename
        :param str cert_chain: certificate chain filename

        :returns: Success
        :rtype: bool

        """
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
            # Throw some "can't find all of the directives error"
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
                            (vhost.filep, vhost.addrs))
        self.save_notes += "\tSSLCertificateFile %s\n" % cert
        self.save_notes += "\tSSLCertificateKeyFile %s\n" % key
        if cert_chain:
            self.save_notes += "\tSSLCertificateChainFile %s\n" % cert_chain
        # This is a significant operation, make a checkpoint
        return self.save()

    def choose_virtual_host(self, target_name):
        """ Chooses a virtual host based on the given domain name.

        .. todo:: This should maybe return list if no obvious answer
            is presented.

        :param str name: domain name

        :returns: ssl vhost associated with name
        :rtype: :class:`letsencrypt.client.apache.obj.VH`

        """
        # Allows for domain names to be associated with a virtual host
        # Client isn't using create_dn_server_assoc(self, dn, vh) yet
        for domain, vhost in self.assoc:
            if domain == target_name:
                return vhost
        # Check for servernames/aliases for ssl hosts
        for vhost in self.vhosts:
            if vhost.ssl and target_name in vhost.names:
                return vhost
        # Checking for domain name in vhost address
        # This technique is not recommended by Apache but is technically valid
        target_addr = obj.Addr((target_name, "443"))
        for vhost in self.vhosts:
            if target_addr in vhost.addrs:
                return vhost

        # Check for non ssl vhosts with servernames/aliases == 'name'
        for vhost in self.vhosts:
            if not vhost.ssl and target_name in vhost.names:
                return self.make_vhost_ssl(vhost)

        # No matches, search for the default
        for vhost in self.vhosts:
            if "_defualt_:443" in vhost.addrs:
                return vhost
        return None

    def create_dn_server_assoc(self, domain, vhost):
        """Create an association between a domain name and virtual host.

        Helps to choose an appropriate vhost

        :param str domain: domain name to associate

        :param vhost: virtual host to associate with domain
        :type vhost: :class:`letsencrypt.client.apache.obj.VH`

        """
        self.assoc[domain] = vhost

    def get_all_names(self):
        """Returns all names found in the Apache Configuration.

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

    def _add_servernames(self, host):
        """Helper function for get_virtual_hosts().

        :param host: In progress vhost whose names will be added
        :type host: :class:`letsencrypt.client.apache.obj.VH`

        """
        name_match = self.aug.match(("%s//*[self::directive=~regexp('%s')] | "
                                     "%s//*[self::directive=~regexp('%s')]" %
                                     (host.path,
                                      parser.case_i('ServerName'),
                                      host.path,
                                      parser.case_i('ServerAlias'))))

        for name in name_match:
            args = self.aug.match(name + "/*")
            for arg in args:
                host.add_name(self.aug.get(arg))

    def _create_vhost(self, path):
        """Used by get_virtual_hosts to create vhost objects

        :param str path: Augeas path to virtual host

        :returns: newly created vhost
        :rtype: :class:`letsencrypt.client.apache.obj.VH`

        """
        addrs = set()
        args = self.aug.match(path + "/arg")
        for arg in args:
            addrs.add(obj.Addr.fromstring(self.aug.get(arg)))
        is_ssl = False

        if self.parser.find_dir(
                parser.case_i("SSLEngine"), parser.case_i("on"), path):
            is_ssl = True

        filename = get_file_path(path)
        is_enabled = self.is_site_enabled(filename)
        vhost = obj.VH(filename, path, addrs, is_ssl, is_enabled)
        self._add_servernames(vhost)
        return vhost

    # TODO: make "sites-available" a configurable directory
    def get_virtual_hosts(self):
        """Returns list of virtual hosts found in the Apache configuration.

        :returns: List of :class:`letsencrypt.client.apache.obj.VH` objects
            found in configuration
        :rtype: list

        """
        # Search sites-available, httpd.conf for possible virtual hosts
        paths = self.aug.match(
            ("/files%ssites-available//*[label()=~regexp('%s')]" %
             (self.parser.root, parser.case_i('VirtualHost'))))
        vhs = []

        for path in paths:
            vhs.append(self._create_vhost(path))

        return vhs

    # pylint: disable=anomalous-backslash-in-string
    def is_name_vhost(self, target_addr):
        """Returns if vhost is a name based vhost

        NameVirtualHost was deprecated in Apache 2.4 as all VirtualHosts are
        now NameVirtualHosts. If version is earlier than 2.4, check if addr
        has a NameVirtualHost directive in the Apache config

        :param str addr: vhost address ie. \*:443

        :returns: Success
        :rtype: bool

        """
        # Mixed and matched wildcard NameVirtualHost with VirtualHost
        # behavior is undefined. Make sure that an exact match exists

        # search for NameVirtualHost directive for ip_addr
        # note ip_addr can be FQDN although Apache does not recommend it
        return (self.version >= (2, 4) or
                self.parser.find_dir(
                    parser.case_i("NameVirtualHost"),
                    parser.case_i(str(target_addr))))

    def add_name_vhost(self, addr):
        """Adds NameVirtualHost directive for given address.

        :param str addr: Address that will be added as NameVirtualHost directive

        """
        path = self.parser.add_dir_to_ifmodssl(
            parser.get_aug_path(
                self.parser.loc["name"]), "NameVirtualHost", str(addr))

        self.save_notes += "Setting %s to be NameBasedVirtualHost\n" % addr
        self.save_notes += "\tDirective added to %s\n" % path

    def _prepare_server_https(self):
        """Prepare the server for HTTPS.

        Make sure that the ssl_module is loaded and that the server
        is appropriately listening on port 443.

        """
        if not check_ssl_loaded():
            logging.info("Loading mod_ssl into Apache Server")
            enable_mod("ssl")

        # Check for Listen 443
        # Note: This could be made to also look for ip:443 combo
        # TODO: Need to search only open directives and IfMod mod_ssl.c
        if len(self.parser.find_dir(parser.case_i("Listen"), "443")) == 0:
            logging.debug("No Listen 443 directive found")
            logging.debug("Setting the Apache Server to Listen on port 443")
            path = self.parser.add_dir_to_ifmodssl(
                parser.get_aug_path(self.parser.loc["listen"]), "Listen", "443")
            self.save_notes += "Added Listen 443 directive to %s\n" % path

    def make_server_sni_ready(self, vhost, default_addr="*:443"):
        """Checks to see if the server is ready for SNI challenges.

        :param vhost: VHost to check SNI compatibility
        :type vhost: :class:`letsencrypt.client.apache.obj.VH`

        :param str default_addr: TODO - investigate function further

        """
        if self.version >= (2, 4):
            return
        # Check for NameVirtualHost
        # First see if any of the vhost addresses is a _default_ addr
        for addr in vhost.addrs:
            if addr.get_addr() == "_default_":
                if not self.is_name_vhost(default_addr):
                    logging.debug("Setting all VirtualHosts on %s to be "
                                  "name based vhosts", default_addr)
                    self.add_name_vhost(default_addr)

        # No default addresses... so set each one individually
        for addr in vhost.addrs:
            if not self.is_name_vhost(addr):
                logging.debug("Setting VirtualHost at %s to be a name "
                              "based virtual host", addr)
                self.add_name_vhost(addr)

    def make_vhost_ssl(self, nonssl_vhost):
        """Makes an ssl_vhost version of a nonssl_vhost.

        Duplicates vhost and adds default ssl options
        New vhost will reside as (nonssl_vhost.path) + CONFIG.LE_VHOST_EXT

        :param nonssl_vhost: Valid VH that doesn't have SSLEngine on
        :type nonssl_vhost: :class:`letsencrypt.client.apache.obj.VH`

        :returns: SSL vhost
        :rtype: :class:`letsencrypt.client.apache.obj.VH`

        """
        avail_fp = nonssl_vhost.filep
        # Get filepath of new ssl_vhost
        if avail_fp.endswith(".conf"):
            ssl_fp = avail_fp[:-(len(".conf"))] + CONFIG.LE_VHOST_EXT
        else:
            ssl_fp = avail_fp + CONFIG.LE_VHOST_EXT

        # First register the creation so that it is properly removed if
        # configuration is rolled back
        self.register_file_creation(False, ssl_fp)

        try:
            orig_file = open(avail_fp, 'r')
            new_file = open(ssl_fp, 'w')
            new_file.write("<IfModule mod_ssl.c>\n")
            for line in orig_file:
                new_file.write(line)
            new_file.write("</IfModule>\n")
        except IOError:
            logging.fatal("Error writing/reading to file in make_vhost_ssl")
            sys.exit(49)
        finally:
            orig_file.close()
            new_file.close()

        self.aug.load()

        ssl_addrs = set()

        # change address to address:443
        addr_match = "/files%s//* [label()=~regexp('%s')]/arg"
        ssl_addr_p = self.aug.match(
            addr_match % (ssl_fp, parser.case_i('VirtualHost')))

        for i in range(len(ssl_addr_p)):
            ssl_addr_arg = obj.Addr.fromstring(
                str(self.aug.get(ssl_addr_p[i])))
            ssl_addr_arg.set_port("443")
            self.aug.set(ssl_addr_p[i], str(ssl_addr_arg))
            ssl_addrs.add(ssl_addr_arg)

        # Add directives
        vh_p = self.aug.match(("/files%s//* [label()=~regexp('%s')]" %
                               (ssl_fp, parser.case_i('VirtualHost'))))
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
        self.save_notes += 'Created ssl vhost at %s\n' % ssl_fp
        self.save()

        # We know the length is one because of the assertion above
        ssl_vhost = self._create_vhost(vh_p[0])
        self.vhosts.append(ssl_vhost)

        # NOTE: Searches through Augeas seem to ruin changes to directives
        #       The configuration must also be saved before being searched
        #       for the new directives; For these reasons... this is tacked
        #       on after fully creating the new vhost
        need_to_save = False
        # See if the exact address appears in any other vhost
        for addr in ssl_addrs:
            for vhost in self.vhosts:
                if (ssl_vhost.filep != vhost.filep and addr in vhost.addrs and
                        not self.is_name_vhost(addr)):
                    self.add_name_vhost(addr)
                    logging.info("Enabling NameVirtualHosts on %s", addr)
                    need_to_save = True

        if need_to_save:
            self.save()

        return ssl_vhost

    def enable_redirect(self, ssl_vhost):
        """Redirect all equivalent HTTP traffic to ssl_vhost.

        Adds Redirect directive to the port 80 equivalent of ssl_vhost
        First the function attempts to find the vhost with equivalent
        ip addresses that serves on non-ssl ports
        The function then adds the directive

        :param ssl_vhost: Destination of traffic, an ssl enabled vhost
        :type ssl_vhost: :class:`letsencrypt.client.apache.obj.VH`

        :returns: Success, general_vhost (HTTP vhost)
        :rtype: (bool, :class:`letsencrypt.client.apache.obj.VH`)

        """
        # TODO: Enable check to see if it is already there
        #       to avoid the extra restart
        enable_mod("rewrite")

        general_v = self._general_vhost(ssl_vhost)
        if general_v is None:
            # Add virtual_server with redirect
            logging.debug(
                "Did not find http version of ssl virtual host... creating")
            return self.create_redirect_vhost(ssl_vhost)
        else:
            # Check if redirection already exists
            exists, code = self.existing_redirect(general_v)
            if exists:
                if code == 0:
                    logging.debug("Redirect already added")
                    return True, general_v
                else:
                    logging.debug("Unknown redirect exists for this vhost")
                    return False, general_v
            # Add directives to server
            self.parser.add_dir(general_v.path, "RewriteEngine", "On")
            self.parser.add_dir(
                general_v.path, "RewriteRule", CONFIG.REWRITE_HTTPS_ARGS)
            self.save_notes += ('Redirecting host in %s to ssl vhost in %s\n' %
                                (general_v.filep, ssl_vhost.filep))
            self.save()
            return True, general_v

    def existing_redirect(self, vhost):
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
        :type vhost: :class:`letsencrypt.client.apache.obj.VH`

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
        if len(rewrite_path) == len(CONFIG.REWRITE_HTTPS_ARGS):
            for idx, match in enumerate(rewrite_path):
                if self.aug.get(match) != CONFIG.REWRITE_HTTPS_ARGS[idx]:
                    # Not a letsencrypt https rewrite
                    return True, 2
            # Existing letsencrypt https rewrite rule is in place
            return True, 0
        # Rewrite path exists but is not a letsencrypt https rule
        return True, 2

    def create_redirect_vhost(self, ssl_vhost):
        """Creates an http_vhost specifically to redirect for the ssl_vhost.

        :param ssl_vhost: ssl vhost
        :type ssl_vhost: :class:`letsencrypt.client.apache.obj.VH`

        :returns: Success, vhost
        :rtype: (bool, :class:`letsencrypt.client.apache.obj.VH`)

        """
        # Consider changing this to a dictionary check
        # Make sure adding the vhost will be safe
        conflict, host_or_addrs = self._conflicting_host(ssl_vhost)
        if conflict:
            return False, host_or_addrs

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
                         "ErrorLog /var/log/apache2/redirect.error.log\n"
                         "LogLevel warn\n"
                         "</VirtualHost>\n"
                         % (servername, serveralias,
                            " ".join(CONFIG.REWRITE_HTTPS_ARGS)))

        # Write out the file
        # This is the default name
        redirect_filename = "le-redirect.conf"

        # See if a more appropriate name can be applied
        if len(ssl_vhost.names) > 0:
            # Sanity check...
            # make sure servername doesn't exceed filename length restriction
            if ssl_vhost.names[0] < (255-23):
                redirect_filename = "le-redirect-%s.conf" % ssl_vhost.names[0]

        redirect_filepath = ("%ssites-available/%s" %
                             (self.parser.root, redirect_filename))

        # Register the new file that will be created
        # Note: always register the creation before writing to ensure file will
        # be removed in case of unexpected program exit
        self.register_file_creation(False, redirect_filepath)

        # Write out file
        with open(redirect_filepath, 'w') as redirect_fd:
            redirect_fd.write(redirect_file)
        logging.info("Created redirect file: %s", redirect_filename)

        self.aug.load()
        # Make a new vhost data structure and add it to the lists
        new_fp = self.parser.root + "sites-available/" + redirect_filename
        new_vhost = self._create_vhost(parser.get_aug_path(new_fp))
        self.vhosts.append(new_vhost)

        # Finally create documentation for the change
        self.save_notes += ('Created a port 80 vhost, %s, for redirection to '
                            'ssl vhost %s\n' %
                            (new_vhost.filep, ssl_vhost.filep))

        return True, new_vhost

    def _conflicting_host(self, ssl_vhost):
        """Checks for conflicting HTTP vhost for ssl_vhost.

        Checks for a conflicting host, such that a new port 80 host could not
        be created without ruining the apache config
        Used with redirection

        returns: conflict, host_or_addrs - boolean
        if conflict: returns conflicting vhost
        if not conflict: returns space separated list of new host addrs

        :param ssl_vhost: SSL Vhost to check for possible port 80 redirection
        :type ssl_vhost: :class:`letsencrypt.client.apache.obj.VH`

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
        :type ssl_vhost: :class:`letsencrypt.client.apache.obj.VH`

        :returns: HTTP vhost or None if unsuccessful
        :rtype: :class:`letsencrypt.client.apache.obj.VH` or None

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

    # TODO: Handle ths as outlined in Interfaces.
    def enable_ocsp_stapling(self, ssl_vhost):
        """Enable OCSP Stapling."""
        return False

    def enable_hsts(self, ssl_vhost):
        """Enable HSTS."""
        return False

    def get_all_certs_keys(self):
        """ Find all existing keys, certs from configuration.

        Retrieve all certs and keys set in VirtualHosts on the Apache server

        :returns: list of tuples with form [(cert, key, path)]
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

        .. todo:: fix hardcoded sites-enabled

        :param str avail_fp: Complete file path of available site

        :returns: Success
        :rtype: bool

        """
        enabled_dir = os.path.join(self.parser.root, "sites-enabled/")
        for entry in os.listdir(enabled_dir):
            if os.path.realpath(enabled_dir + entry) == avail_fp:
                return True

        return False

    def enable_site(self, vhost):
        """Enables an available site, Apache restart required.

        .. todo:: This function should number subdomains before the domain vhost

        .. todo:: Make sure link is not broken...

        :param vhost: vhost to enable
        :type vhost: :class:`letsencrypt.client.apache.obj.VH`

        :returns: Success
        :rtype: bool

        """
        if self.is_site_enabled(vhost.filep):
            return True

        if "/sites-available/" in vhost.filep:
            enabled_path = ("%ssites-enabled/%s" %
                            (self.parser.root, os.path.basename(vhost.filep)))
            self.register_file_creation(False, enabled_path)
            os.symlink(vhost.filep, enabled_path)
            vhost.enabled = True
            logging.info("Enabling available site: %s", vhost.filep)
            self.save_notes += 'Enabled site %s\n' % vhost.filep
            return True
        return False

    def restart(self):  # pylint: disable=no-self-use
        """Restarts apache server.

        :returns: Success
        :rtype: bool

        """
        return apache_restart()

    def config_test(self):
        """Check the configuration of Apache for errors.

        :returns: Success
        :rtype: bool

        """
        try:
            proc = subprocess.Popen(
                ['sudo', '/usr/sbin/apache2ctl', 'configtest'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE)
            text = proc.communicate()
        except (OSError, ValueError):
            logging.fatal("Unable to run /usr/sbin/apache2ctl configtest")
            sys.exit(1)

        if proc.returncode != 0:
            # Enter recovery routine...
            logging.error("Configtest failed")
            logging.error(text[0])
            logging.error(text[1])
            return False

        return True

    def get_version(self):  # pylint: disable=no-self-use
        """Return version of Apache Server.

        Version is returned as tuple. (ie. 2.4.7 = (2, 4, 7))

        :returns: version
        :rtype: tuple

        :raises errors.LetsEncryptConfiguratorError:
            Unable to find Apache version

        """
        try:
            proc = subprocess.Popen(
                [CONFIG.APACHE_CTL, '-v'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE)
            text = proc.communicate()[0]
        except (OSError, ValueError):
            raise errors.LetsEncryptConfiguratorError(
                "Unable to run %s -v" % CONFIG.APACHE_CTL)

        regex = re.compile(r"Apache/([0-9\.]*)", re.IGNORECASE)
        matches = regex.findall(text)

        if len(matches) != 1:
            raise errors.LetsEncryptConfiguratorError(
                "Unable to find Apache version")

        return tuple([int(i) for i in matches[0].split('.')])

    def verify_setup(self):
        """Verify the setup to ensure safe operating environment.

        Make sure that files/directories are setup with appropriate permissions
        Aim for defensive coding... make sure all input files
        have permissions of root

        """
        uid = os.geteuid()
        le_util.make_or_verify_dir(self.direc["config"], 0o755, uid)
        le_util.make_or_verify_dir(self.direc["work"], 0o755, uid)
        le_util.make_or_verify_dir(self.direc["backup"], 0o755, uid)

    ###########################################################################
    # Challenges Section
    ###########################################################################

    # TODO: Change list_sni_tuple to namedtuple. Also include key within tuple.
    #       This allows the keys to be different for each SNI challenge

    def perform(self, chall_dict):
        """Perform the configuration related challenge.

        :param dict chall_dict: Dictionary representing a challenge.

        """

        if chall_dict.get("type", "") == 'dvsni':
            return self.dvsni_perform(chall_dict)
        return None

    def dvsni_perform(self, chall_dict):
        """Peform a DVSNI challenge.

        `chall_dict` composed of:

        list_sni_tuple:
            List of tuples with form `(name, r, nonce)`, where
            `name` (`str`), `r` (base64 `str`), `nonce` (hex `str`)

        dvsni_key:
            DVSNI key (:class:`letsencrypt.client.client.Client.Key`)

        :param dict chall_dict: dvsni challenge - see documentation

        """
        # Save any changes to the configuration as a precaution
        # About to make temporary changes to the config
        self.save()

        # Do weak validation that challenge is of expected type
        if not ("list_sni_tuple" in chall_dict and "dvsni_key" in chall_dict):
            logging.fatal("Incorrect parameter given to Apache DVSNI challenge")
            logging.fatal("Chall dict: %s", chall_dict)
            sys.exit(1)

        addresses = []
        default_addr = "*:443"
        for tup in chall_dict["list_sni_tuple"]:
            vhost = self.choose_virtual_host(tup[0])
            if vhost is None:
                logging.error(
                    "No vhost exists with servername or alias of: %s", tup[0])
                logging.error("No _default_:443 vhost exists")
                logging.error("Please specify servernames in the Apache config")
                return None

            # TODO - @jdkasten review this code to make sure it makes sense
            self.make_server_sni_ready(vhost, default_addr)

            for addr in vhost.addrs:
                if "_default_" == addr.get_addr():
                    addresses.append([default_addr])
                    break
            else:
                addresses.append(list(vhost.addrs))

        responses = []

        # Create all of the challenge certs
        for tup in chall_dict["list_sni_tuple"]:
            cert_path = self.dvsni_get_cert_file(tup[2])
            self.register_file_creation(cert_path)
            s_b64 = challenge_util.dvsni_gen_cert(
                cert_path, tup[0], tup[1], tup[2], chall_dict["dvsni_key"])

            responses.append({"type": "dvsni", "s": s_b64})

        # Setup the configuration
        self.dvsni_mod_config(chall_dict["list_sni_tuple"],
                              chall_dict["dvsni_key"],
                              addresses)

        # Save reversible changes and restart the server
        self.save("SNI Challenge", True)
        self.restart()

        return responses

    def cleanup(self):
        """Revert all challenges."""

        self.revert_challenge_config()
        self.restart()

    # TODO: Variable names
    def dvsni_mod_config(self, list_sni_tuple, dvsni_key,
                         ll_addrs):
        """Modifies Apache config files to include challenge vhosts.

        Result: Apache config includes virtual servers for issued challs

        :param list list_sni_tuple: list of tuples with the form
            `(addr, y, nonce)`, where `addr` is `str`, `y` is `bytearray`,
            and nonce is hex `str`

        :param dvsni_key: DVSNI key
        :type dvsni_key: :class:`letsencrypt.client.client.Client.Key`

        :param list ll_addrs: list of list of
            :class:`letsencrypt.client.apache.obj.Addr` to apply

        """
        # WARNING: THIS IS A POTENTIAL SECURITY VULNERABILITY
        # THIS SHOULD BE HANDLED BY THE PACKAGE MANAGER
        # AND TAKEN OUT BEFORE RELEASE, INSTEAD
        # SHOWING A NICE ERROR MESSAGE ABOUT THE PROBLEM

        # Check to make sure options-ssl.conf is installed
        # pylint: disable=no-member
        if not os.path.isfile(CONFIG.OPTIONS_SSL_CONF):
            dist_conf = pkg_resources.resource_filename(
                __name__, os.path.basename(CONFIG.OPTIONS_SSL_CONF))
            shutil.copyfile(dist_conf, CONFIG.OPTIONS_SSL_CONF)

        # TODO: Use ip address of existing vhost instead of relying on FQDN
        config_text = "<IfModule mod_ssl.c> \n"
        for idx, lis in enumerate(ll_addrs):
            config_text += self.get_config_text(
                list_sni_tuple[idx][2], lis, dvsni_key.file)
        config_text += "</IfModule> \n"

        self.dvsni_conf_include_check(self.parser.loc["default"])
        self.register_file_creation(True, CONFIG.APACHE_CHALLENGE_CONF)

        with open(CONFIG.APACHE_CHALLENGE_CONF, 'w') as new_conf:
            new_conf.write(config_text)

    def dvsni_conf_include_check(self, main_config):
        """Adds DVSNI challenge conf file into configuration.

        Adds DVSNI challenge include file if it does not already exist
        within mainConfig

        :param str main_config: file path to main user apache config file

        """
        if len(self.parser.find_dir(
                parser.case_i("Include"), CONFIG.APACHE_CHALLENGE_CONF)) == 0:
            # print "Including challenge virtual host(s)"
            self.parser.add_dir(parser.get_aug_path(main_config),
                                "Include", CONFIG.APACHE_CHALLENGE_CONF)

    def get_config_text(self, nonce, ip_addrs, dvsni_key_file):
        """Chocolate virtual server configuration text

        :param str nonce: hex form of nonce
        :param list ip_addrs: addresses of challenged domain
            :class:`list` of type :class:`letsencrypt.client.apache.obj.Addr`
        :param str dvsni_key_file: Path to key file

        :returns: virtual host configuration text
        :rtype: str

        """
        ips = " ".join(str(i) for i in ip_addrs)
        return ("<VirtualHost " + ips + ">\n"
                "ServerName " + nonce + CONFIG.INVALID_EXT + "\n"
                "UseCanonicalName on\n"
                "SSLStrictSNIVHostCheck on\n"
                "\n"
                "LimitRequestBody 1048576\n"
                "\n"
                "Include " + self.parser.loc["ssl_options"] + "\n"
                "SSLCertificateFile " + self.dvsni_get_cert_file(nonce) + "\n"
                "SSLCertificateKeyFile " + dvsni_key_file + "\n"
                "\n"
                "DocumentRoot " + self.direc["config"] + "challenge_page/\n"
                "</VirtualHost>\n\n")

    def dvsni_get_cert_file(self, nonce):
        """Returns standardized name for challenge certificate.

        :param str nonce: hex form of nonce

        :returns: certificate file name
        :rtype: str

        """
        return self.direc["work"] + nonce + ".crt"


def enable_mod(mod_name):
    """Enables module in Apache.

    Both enables and restarts Apache so module is active.

    :param str mod_name: Name of the module to enable

    """
    try:
        # Use check_output so the command will finish before reloading
        subprocess.check_call(["sudo", "a2enmod", mod_name],
                              stdout=open("/dev/null", 'w'),
                              stderr=open("/dev/null", 'w'))
        # Hopefully this waits for output
        subprocess.check_call(["sudo", CONFIG.APACHE2, "restart"],
                              stdout=open("/dev/null", 'w'),
                              stderr=open("/dev/null", 'w'))
    except (OSError, subprocess.CalledProcessError) as err:
        logging.error("Error enabling mod_%s", mod_name)
        logging.error("Exception: %s", err)
        sys.exit(1)


def check_ssl_loaded():
    """Checks to see if mod_ssl is loaded

    Currently uses apache2ctl to get loaded module list

    .. todo:: This function is likely fragile to versions/distros

    :returns: If ssl_module is included and active in Apache
    :rtype: bool

    """
    try:
        # p=subprocess.check_output(['sudo', '/usr/sbin/apache2ctl', '-M'],
        #                            stderr=open("/dev/null", 'w'))
        proc = subprocess.Popen([CONFIG.APACHE_CTL, '-M'],
                                stdout=subprocess.PIPE,
                                stderr=open(
                                    "/dev/null", 'w')).communicate()[0]
    except (OSError, ValueError):
        logging.error(
            "Error accessing %s for loaded modules!", CONFIG.APACHE_CTL)
        logging.error("This may be caused by an Apache Configuration Error")
        return False

    if "ssl_module" in proc:
        return True
    return False


def apache_restart():
    """Restarts the Apache Server.

    .. todo:: Try to use reload instead. (This caused timing problems before)
    .. todo:: This should be written to use the process return code.

    """
    try:
        proc = subprocess.Popen([CONFIG.APACHE2, 'restart'],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        text = proc.communicate()

        if proc.returncode != 0:
            # Enter recovery routine...
            logging.error("Configtest failed")
            logging.error(text[0])
            logging.error(text[1])
            return False

    except (OSError, ValueError):
        logging.fatal(
            "Apache Restart Failed - Please Check the Configuration")
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
