"""Apache Configuration based off of Augeas Configurator."""
# pylint: disable=too-many-lines
import filecmp
import logging
import os
import re
import shutil
import socket
import time

import zope.component
import zope.interface

from acme import challenges

from letsencrypt import errors
from letsencrypt import interfaces
from letsencrypt import le_util

from letsencrypt.plugins import common

from letsencrypt_apache import augeas_configurator
from letsencrypt_apache import constants
from letsencrypt_apache import display_ops
from letsencrypt_apache import tls_sni_01
from letsencrypt_apache import obj
from letsencrypt_apache import parser

from collections import defaultdict

logger = logging.getLogger(__name__)


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


# TODO: Verify permissions on configuration root... it is easier than
#     checking permissions on each of the relative directories and less error
#     prone.
# TODO: Write a server protocol finder. Listen <port> <protocol> or
#     Protocol <protocol>.  This can verify partial setups are correct
# TODO: Add directives to sites-enabled... not sites-available.
#     sites-available doesn't allow immediate find_dir search even with save()
#     and load()

class ApacheConfigurator(augeas_configurator.AugeasConfigurator):
    # pylint: disable=too-many-instance-attributes,too-many-public-methods
    """Apache configurator.

    State of Configurator: This code has been been tested and built for Ubuntu
    14.04 Apache 2.4 and it works for Ubuntu 12.04 Apache 2.2

    :ivar config: Configuration.
    :type config: :class:`~letsencrypt.interfaces.IConfig`

    :ivar parser: Handles low level parsing
    :type parser: :class:`~letsencrypt_apache.parser`

    :ivar tup version: version of Apache
    :ivar list vhosts: All vhosts found in the configuration
        (:class:`list` of :class:`~letsencrypt_apache.obj.VirtualHost`)

    :ivar dict assoc: Mapping between domains and vhosts

    """
    zope.interface.implements(interfaces.IAuthenticator, interfaces.IInstaller)
    zope.interface.classProvides(interfaces.IPluginFactory)

    description = "Apache Web Server - Alpha"

    @classmethod
    def add_parser_arguments(cls, add):
        add("enmod", default=constants.os_constant("enmod"),
            help="Path to the Apache 'a2enmod' binary.")
        add("dismod", default=constants.os_constant("dismod"),
            help="Path to the Apache 'a2dismod' binary.")
        add("le-vhost-ext", default=constants.os_constant("le_vhost_ext"),
            help="SSL vhost configuration extension.")
        add("server-root", default=constants.os_constant("server_root"),
            help="Apache server root directory.")
        add("vhost-root", default=constants.os_constant("vhost_root"),
            help="Apache server VirtualHost configuration root")
        add("challenge-location",
            default=constants.os_constant("challenge_location"),
            help="Directory path for challenge configuration.")
        add("handle-modules", default=constants.os_constant("handle_mods"),
            help="Let installer handle enabling required modules for you." +
                 "(Only Ubuntu/Debian currently)")
        add("handle-sites", default=constants.os_constant("handle_sites"),
            help="Let installer handle enabling sites for you." +
                 "(Only Ubuntu/Debian currently)")
        le_util.add_deprecated_argument(add, argument_name="ctl", nargs=1)
        le_util.add_deprecated_argument(
            add, argument_name="init-script", nargs=1)

    def __init__(self, *args, **kwargs):
        """Initialize an Apache Configurator.

        :param tup version: version of Apache as a tuple (2, 4, 7)
            (used mostly for unittesting)

        """
        version = kwargs.pop("version", None)
        super(ApacheConfigurator, self).__init__(*args, **kwargs)

        # Add name_server association dict
        self.assoc = dict()
        # Outstanding challenges
        self._chall_out = set()

        # These will be set in the prepare function
        self.parser = None
        self.version = version
        self.vhosts = None
        self._enhance_func = {"redirect": self._enable_redirect,
                              "ensure-http-header": self._set_http_header}

    @property
    def mod_ssl_conf(self):
        """Full absolute path to SSL configuration file."""
        return os.path.join(self.config.config_dir,
                            constants.MOD_SSL_CONF_DEST)

    def prepare(self):
        """Prepare the authenticator/installer.

        :raises .errors.NoInstallationError: If Apache configs cannot be found
        :raises .errors.MisconfigurationError: If Apache is misconfigured
        :raises .errors.NotSupportedError: If Apache version is not supported
        :raises .errors.PluginError: If there is any other error

        """
        # Verify Apache is installed
        if not le_util.exe_exists(constants.os_constant("restart_cmd")[0]):
            raise errors.NoInstallationError

        # Make sure configuration is valid
        self.config_test()

        # Set Version
        if self.version is None:
            self.version = self.get_version()
        if self.version < (2, 2):
            raise errors.NotSupportedError(
                "Apache Version %s not supported.", str(self.version))

        if not self._check_aug_version():
            raise errors.NotSupportedError(
                "Apache plugin support requires libaugeas0 and augeas-lenses "
                "version 1.2.0 or higher, please make sure you have you have "
                "those installed.")

        self.parser = parser.ApacheParser(
            self.aug, self.conf("server-root"), self.conf("vhost-root"),
            self.version)
        # Check for errors in parsing files with Augeas
        self.check_parsing_errors("httpd.aug")

        # Get all of the available vhosts
        self.vhosts = self.get_virtual_hosts()

        install_ssl_options_conf(self.mod_ssl_conf)

    def _check_aug_version(self):
        """ Checks that we have recent enough version of libaugeas.
        If augeas version is recent enough, it will support case insensitive
        regexp matching"""

        self.aug.set("/test/path/testing/arg", "aRgUMeNT")
        try:
            matches = self.aug.match(
                "/test//*[self::arg=~regexp('argument', 'i')]")
        except RuntimeError:
            self.aug.remove("/test/path")
            return False
        self.aug.remove("/test/path")
        return matches

    def deploy_cert(self, domain, cert_path, key_path,
                    chain_path=None, fullchain_path=None):
        """Deploys certificate to specified virtual host.

        Currently tries to find the last directives to deploy the cert in
        the VHost associated with the given domain. If it can't find the
        directives, it searches the "included" confs. The function verifies
        that it has located the three directives and finally modifies them
        to point to the correct destination. After the certificate is
        installed, the VirtualHost is enabled if it isn't already.

        .. todo:: Might be nice to remove chain directive if none exists
                  This shouldn't happen within letsencrypt though

        :raises errors.PluginError: When unable to deploy certificate due to
            a lack of directives

        """
        vhost = self.choose_vhost(domain)
        self._clean_vhost(vhost)

        # This is done first so that ssl module is enabled and cert_path,
        # cert_key... can all be parsed appropriately
        self.prepare_server_https("443")

        path = {"cert_path": self.parser.find_dir("SSLCertificateFile",
                                                  None, vhost.path),
                "cert_key": self.parser.find_dir("SSLCertificateKeyFile",
                                                 None, vhost.path)}

        # Only include if a certificate chain is specified
        if chain_path is not None:
            path["chain_path"] = self.parser.find_dir(
                "SSLCertificateChainFile", None, vhost.path)

        if not path["cert_path"] or not path["cert_key"]:
            # Throw some can't find all of the directives error"
            logger.warn(
                "Cannot find a cert or key directive in %s. "
                "VirtualHost was not modified", vhost.path)
            # Presumably break here so that the virtualhost is not modified
            raise errors.PluginError(
                "Unable to find cert and/or key directives")

        logger.info("Deploying Certificate to VirtualHost %s", vhost.filep)
        logger.debug("Apache version is %s",
                     ".".join(str(i) for i in self.version))

        if self.version < (2, 4, 8) or (chain_path and not fullchain_path):
            # install SSLCertificateFile, SSLCertificateKeyFile,
            # and SSLCertificateChainFile directives
            set_cert_path = cert_path
            self.aug.set(path["cert_path"][-1], cert_path)
            self.aug.set(path["cert_key"][-1], key_path)
            if chain_path is not None:
                self.parser.add_dir(vhost.path,
                                    "SSLCertificateChainFile", chain_path)
            else:
                raise errors.PluginError("--chain-path is required for your "
                                         "version of Apache")
        else:
            if not fullchain_path:
                raise errors.PluginError("Please provide the --fullchain-path\
 option pointing to your full chain file")
            set_cert_path = fullchain_path
            self.aug.set(path["cert_path"][-1], fullchain_path)
            self.aug.set(path["cert_key"][-1], key_path)

        # Save notes about the transaction that took place
        self.save_notes += ("Changed vhost at %s with addresses of %s\n"
                            "\tSSLCertificateFile %s\n"
                            "\tSSLCertificateKeyFile %s\n" %
                            (vhost.filep,
                             ", ".join(str(addr) for addr in vhost.addrs),
                             set_cert_path, key_path))
        if chain_path is not None:
            self.save_notes += "\tSSLCertificateChainFile %s\n" % chain_path

        # Make sure vhost is enabled if distro with enabled / available
        if self.conf("handle-sites"):
            if not vhost.enabled:
                self.enable_site(vhost)

    def choose_vhost(self, target_name, temp=False):
        """Chooses a virtual host based on the given domain name.

        If there is no clear virtual host to be selected, the user is prompted
        with all available choices.

        The returned vhost is guaranteed to have TLS enabled unless temp is
        True. If temp is True, there is no such guarantee and the result is
        not cached.

        :param str target_name: domain name
        :param bool temp: whether the vhost is only used temporarily

        :returns: ssl vhost associated with name
        :rtype: :class:`~letsencrypt_apache.obj.VirtualHost`

        :raises .errors.PluginError: If no vhost is available or chosen

        """
        # Allows for domain names to be associated with a virtual host
        if target_name in self.assoc:
            return self.assoc[target_name]

        # Try to find a reasonable vhost
        vhost = self._find_best_vhost(target_name)
        if vhost is not None:
            if temp:
                return vhost
            if not vhost.ssl:
                vhost = self.make_vhost_ssl(vhost)

            self._add_servername_alias(target_name, vhost)
            self.assoc[target_name] = vhost
            return vhost

        return self._choose_vhost_from_list(target_name, temp)

    def _choose_vhost_from_list(self, target_name, temp=False):
        # Select a vhost from a list
        vhost = display_ops.select_vhost(target_name, self.vhosts)
        if vhost is None:
            logger.error(
                "No vhost exists with servername or alias of: %s. "
                "No vhost was selected. Please specify servernames "
                "in the Apache config", target_name)
            raise errors.PluginError("No vhost selected")
        elif temp:
            return vhost
        elif not vhost.ssl:
            addrs = self._get_proposed_addrs(vhost, "443")
            # TODO: Conflicts is too conservative
            if not any(vhost.enabled and vhost.conflicts(addrs) for
                       vhost in self.vhosts):
                vhost = self.make_vhost_ssl(vhost)
            else:
                logger.error(
                    "The selected vhost would conflict with other HTTPS "
                    "VirtualHosts within Apache. Please select another "
                    "vhost or add ServerNames to your configuration.")
                raise errors.PluginError(
                    "VirtualHost not able to be selected.")

        self._add_servername_alias(target_name, vhost)
        self.assoc[target_name] = vhost
        return vhost

    def _find_best_vhost(self, target_name):
        """Finds the best vhost for a target_name.

        This does not upgrade a vhost to HTTPS... it only finds the most
        appropriate vhost for the given target_name.

        :returns: VHost or None

        """
        # Points 4 - Servername SSL
        # Points 3 - Address name with SSL
        # Points 2 - Servername no SSL
        # Points 1 - Address name with no SSL
        best_candidate = None
        best_points = 0
        for vhost in self.vhosts:
            if vhost.modmacro is True:
                continue
            if target_name in vhost.get_names():
                points = 2
            elif any(addr.get_addr() == target_name for addr in vhost.addrs):
                points = 1
            else:
                # No points given if names can't be found.
                # This gets hit but doesn't register
                continue  # pragma: no cover

            if vhost.ssl:
                points += 2

            if points > best_points:
                best_points = points
                best_candidate = vhost

        # No winners here... is there only one reasonable vhost?
        if best_candidate is None:
            # reasonable == Not all _default_ addrs
            vhosts = self._non_default_vhosts()
            # remove mod_macro hosts from reasonable vhosts
            reasonable_vhosts = [vh for vh
                                 in vhosts if vh.modmacro is False]
            if len(reasonable_vhosts) == 1:
                best_candidate = reasonable_vhosts[0]

        return best_candidate

    def _non_default_vhosts(self):
        """Return all non _default_ only vhosts."""
        return [vh for vh in self.vhosts if not all(
            addr.get_addr() == "_default_" for addr in vh.addrs
        )]

    def get_all_names(self):
        """Returns all names found in the Apache Configuration.

        :returns: All ServerNames, ServerAliases, and reverse DNS entries for
                  virtual host addresses
        :rtype: set

        """
        all_names = set()

        vhost_macro = []

        for vhost in self.vhosts:
            all_names.update(vhost.get_names())
            if vhost.modmacro:
                vhost_macro.append(vhost.filep)

            for addr in vhost.addrs:
                if common.hostname_regex.match(addr.get_addr()):
                    all_names.add(addr.get_addr())
                else:
                    name = self.get_name_from_ip(addr)
                    if name:
                        all_names.add(name)

        if len(vhost_macro) > 0:
            zope.component.getUtility(interfaces.IDisplay).notification(
                "Apache mod_macro seems to be in use in file(s):\n{0}"
                "\n\nUnfortunately mod_macro is not yet supported".format(
                    "\n  ".join(vhost_macro)))

        return all_names

    def get_name_from_ip(self, addr):  # pylint: disable=no-self-use
        """Returns a reverse dns name if available.

        :param addr: IP Address
        :type addr: ~.common.Addr

        :returns: name or empty string if name cannot be determined
        :rtype: str

        """
        # If it isn't a private IP, do a reverse DNS lookup
        if not common.private_ips_regex.match(addr.get_addr()):
            try:
                socket.inet_aton(addr.get_addr())
                return socket.gethostbyaddr(addr.get_addr())[0]
            except (socket.error, socket.herror, socket.timeout):
                pass

        return ""

    def _add_servernames(self, host):
        """Helper function for get_virtual_hosts().

        :param host: In progress vhost whose names will be added
        :type host: :class:`~letsencrypt_apache.obj.VirtualHost`

        """
        # Take the final ServerName as each overrides the previous
        servername_match = self.parser.find_dir(
            "ServerName", None, start=host.path, exclude=False)
        serveralias_match = self.parser.find_dir(
            "ServerAlias", None, start=host.path, exclude=False)

        for alias in serveralias_match:
            serveralias = self.parser.get_arg(alias)
            if not host.modmacro:
                host.aliases.add(serveralias)

        if servername_match:
            # Get last ServerName as each overwrites the previous
            servername = self.parser.get_arg(servername_match[-1])
            if not host.modmacro:
                host.name = servername

    def _create_vhost(self, path):
        """Used by get_virtual_hosts to create vhost objects

        :param str path: Augeas path to virtual host

        :returns: newly created vhost
        :rtype: :class:`~letsencrypt_apache.obj.VirtualHost`

        """
        addrs = set()
        args = self.aug.match(path + "/arg")
        for arg in args:
            addrs.add(obj.Addr.fromstring(self.parser.get_arg(arg)))
        is_ssl = False

        if self.parser.find_dir("SSLEngine", "on", start=path, exclude=False):
            is_ssl = True

        # "SSLEngine on" might be set outside of <VirtualHost>
        # Treat vhosts with port 443 as ssl vhosts
        for addr in addrs:
            if addr.get_port() == "443":
                is_ssl = True

        filename = get_file_path(path)
        if self.conf("handle-sites"):
            is_enabled = self.is_site_enabled(filename)
        else:
            is_enabled = True

        macro = False
        if "/macro/" in path.lower():
            macro = True

        vhost = obj.VirtualHost(filename, path, addrs, is_ssl,
                                is_enabled, modmacro=macro)
        self._add_servernames(vhost)
        return vhost

    def get_virtual_hosts(self):
        """Returns list of virtual hosts found in the Apache configuration.

        :returns: List of :class:`~letsencrypt_apache.obj.VirtualHost`
            objects found in configuration
        :rtype: list

        """
        # Search base config, and all included paths for VirtualHosts
        vhs = []
        vhost_paths = {}
        for vhost_path in self.parser.parser_paths.keys():
            paths = self.aug.match(
                ("/files%s//*[label()=~regexp('%s')]" %
                    (vhost_path, parser.case_i("VirtualHost"))))
            for path in paths:
                new_vhost = self._create_vhost(path)
                realpath = os.path.realpath(new_vhost.filep)
                if realpath not in vhost_paths.keys():
                    vhs.append(new_vhost)
                    vhost_paths[realpath] = new_vhost.filep
                elif realpath == new_vhost.filep:
                    # Prefer "real" vhost paths instead of symlinked ones
                    # ex: sites-enabled/vh.conf -> sites-available/vh.conf

                    # remove old (most likely) symlinked one
                    vhs = [v for v in vhs if v.filep != vhost_paths[realpath]]
                    vhs.append(new_vhost)
                    vhost_paths[realpath] = realpath

        return vhs

    def is_name_vhost(self, target_addr):
        """Returns if vhost is a name based vhost

        NameVirtualHost was deprecated in Apache 2.4 as all VirtualHosts are
        now NameVirtualHosts. If version is earlier than 2.4, check if addr
        has a NameVirtualHost directive in the Apache config

        :param letsencrypt_apache.obj.Addr target_addr: vhost address

        :returns: Success
        :rtype: bool

        """
        # Mixed and matched wildcard NameVirtualHost with VirtualHost
        # behavior is undefined. Make sure that an exact match exists

        # search for NameVirtualHost directive for ip_addr
        # note ip_addr can be FQDN although Apache does not recommend it
        return (self.version >= (2, 4) or
                self.parser.find_dir("NameVirtualHost", str(target_addr)))

    def add_name_vhost(self, addr):
        """Adds NameVirtualHost directive for given address.

        :param addr: Address that will be added as NameVirtualHost directive
        :type addr: :class:`~letsencrypt_apache.obj.Addr`

        """
        loc = parser.get_aug_path(self.parser.loc["name"])

        if addr.get_port() == "443":
            path = self.parser.add_dir_to_ifmodssl(
                loc, "NameVirtualHost", [str(addr)])
        else:
            path = self.parser.add_dir(loc, "NameVirtualHost", [str(addr)])

        msg = ("Setting %s to be NameBasedVirtualHost\n"
               "\tDirective added to %s\n" % (addr, path))
        logger.debug(msg)
        self.save_notes += msg

    def prepare_server_https(self, port, temp=False):
        """Prepare the server for HTTPS.

        Make sure that the ssl_module is loaded and that the server
        is appropriately listening on port.

        :param str port: Port to listen on

        """

        self.prepare_https_modules(temp)
        # Check for Listen <port>
        # Note: This could be made to also look for ip:443 combo
        listens = [self.parser.get_arg(x).split()[0] for
                   x in self.parser.find_dir("Listen")]
        # In case no Listens are set (which really is a broken apache config)
        if not listens:
            listens = ["80"]
        if port in listens:
            return
        for listen in listens:
            # For any listen statement, check if the machine also listens on
            # Port 443. If not, add such a listen statement.
            if len(listen.split(":")) == 1:
                # Its listening to all interfaces
                if port not in listens:
                    if port == "443":
                        args = [port]
                    else:
                        # Non-standard ports should specify https protocol
                        args = [port, "https"]
                    self.parser.add_dir_to_ifmodssl(
                        parser.get_aug_path(
                            self.parser.loc["listen"]), "Listen", args)
                    self.save_notes += "Added Listen %s directive to %s\n" % (
                        port, self.parser.loc["listen"])
                    listens.append(port)
            else:
                # The Listen statement specifies an ip
                _, ip = listen[::-1].split(":", 1)
                ip = ip[::-1]
                if "%s:%s" % (ip, port) not in listens:
                    if port == "443":
                        args = ["%s:%s" % (ip, port)]
                    else:
                        # Non-standard ports should specify https protocol
                        args = ["%s:%s" % (ip, port), "https"]
                    self.parser.add_dir_to_ifmodssl(
                        parser.get_aug_path(
                            self.parser.loc["listen"]), "Listen", args)
                    self.save_notes += ("Added Listen %s:%s directive to "
                                        "%s\n") % (ip, port,
                                                   self.parser.loc["listen"])
                    listens.append("%s:%s" % (ip, port))

    def prepare_https_modules(self, temp):
        """Helper method for prepare_server_https, taking care of enabling
        needed modules

        :param boolean temp: If the change is temporary
        """

        if self.conf("handle-modules"):
            if self.version >= (2, 4) and ("socache_shmcb_module" not in
                                           self.parser.modules):
                self.enable_mod("socache_shmcb", temp=temp)
            if "ssl_module" not in self.parser.modules:
                self.enable_mod("ssl", temp=temp)

    def make_addrs_sni_ready(self, addrs):
        """Checks to see if the server is ready for SNI challenges.

        :param addrs: Addresses to check SNI compatibility
        :type addrs: :class:`~letsencrypt_apache.obj.Addr`

        """
        # Version 2.4 and later are automatically SNI ready.
        if self.version >= (2, 4):
            return

        for addr in addrs:
            if not self.is_name_vhost(addr):
                logger.debug("Setting VirtualHost at %s to be a name "
                             "based virtual host", addr)
                self.add_name_vhost(addr)

    def make_vhost_ssl(self, nonssl_vhost):  # pylint: disable=too-many-locals
        """Makes an ssl_vhost version of a nonssl_vhost.

        Duplicates vhost and adds default ssl options
        New vhost will reside as (nonssl_vhost.path) +
        ``letsencrypt_apache.constants.os_constant("le_vhost_ext")``

        .. note:: This function saves the configuration

        :param nonssl_vhost: Valid VH that doesn't have SSLEngine on
        :type nonssl_vhost: :class:`~letsencrypt_apache.obj.VirtualHost`

        :returns: SSL vhost
        :rtype: :class:`~letsencrypt_apache.obj.VirtualHost`

        :raises .errors.PluginError: If more than one virtual host is in
            the file or if plugin is unable to write/read vhost files.

        """
        avail_fp = nonssl_vhost.filep
        ssl_fp = self._get_ssl_vhost_path(avail_fp)

        self._copy_create_ssl_vhost_skeleton(avail_fp, ssl_fp)

        # Reload augeas to take into account the new vhost
        self.aug.load()
        # Get Vhost augeas path for new vhost
        vh_p = self.aug.match("/files%s//* [label()=~regexp('%s')]" %
                              (ssl_fp, parser.case_i("VirtualHost")))
        if len(vh_p) != 1:
            logger.error("Error: should only be one vhost in %s", avail_fp)
            raise errors.PluginError("Currently, we only support "
                                     "configurations with one vhost per file")
        else:
            # This simplifies the process
            vh_p = vh_p[0]

        # Update Addresses
        self._update_ssl_vhosts_addrs(vh_p)

        # Add directives
        self._add_dummy_ssl_directives(vh_p)
        self.save()

        # Log actions and create save notes
        logger.info("Created an SSL vhost at %s", ssl_fp)
        self.save_notes += "Created ssl vhost at %s\n" % ssl_fp
        self.save()

        # We know the length is one because of the assertion above
        # Create the Vhost object
        ssl_vhost = self._create_vhost(vh_p)
        self.vhosts.append(ssl_vhost)

        # NOTE: Searches through Augeas seem to ruin changes to directives
        #       The configuration must also be saved before being searched
        #       for the new directives; For these reasons... this is tacked
        #       on after fully creating the new vhost

        # Now check if addresses need to be added as NameBasedVhost addrs
        # This is for compliance with versions of Apache < 2.4
        self._add_name_vhost_if_necessary(ssl_vhost)

        return ssl_vhost

    def _get_ssl_vhost_path(self, non_ssl_vh_fp):
        # Get filepath of new ssl_vhost
        if non_ssl_vh_fp.endswith(".conf"):
            return non_ssl_vh_fp[:-(len(".conf"))] + self.conf("le_vhost_ext")
        else:
            return non_ssl_vh_fp + self.conf("le_vhost_ext")

    def _sift_line(self, line):
        """Decides whether a line should be copied to a SSL vhost.

        A canonical example of when sifting a line is required:
        When the http vhost contains a RewriteRule that unconditionally
        redirects any request to the https version of the same site.
        e.g:
        RewriteRule ^ https://%{SERVER_NAME}%{REQUEST_URI} [L,QSA,R=permanent]
        Copying the above line to the ssl vhost would cause a
        redirection loop.

        :param str line: a line extracted from the http vhost.

        :returns: True - don't copy line from http vhost to SSL vhost.
        :rtype: bool

        """
        if not line.lstrip().startswith("RewriteRule"):
            return False

        # According to: http://httpd.apache.org/docs/2.4/rewrite/flags.html
        # The syntax of a RewriteRule is:
        # RewriteRule pattern target [Flag1,Flag2,Flag3]
        # i.e. target is required, so it must exist.
        target = line.split()[2].strip()

        # target may be surrounded with quotes
        if target[0] in ("'", '"') and target[0] == target[-1]:
            target = target[1:-1]

        # Sift line if it redirects the request to a HTTPS site
        return target.startswith("https://")

    def _copy_create_ssl_vhost_skeleton(self, avail_fp, ssl_fp):
        """Copies over existing Vhost with IfModule mod_ssl.c> skeleton.

        :param str avail_fp: Pointer to the original available non-ssl vhost
        :param str ssl_fp: Full path where the new ssl_vhost will reside.

        A new file is created on the filesystem.

        """
        # First register the creation so that it is properly removed if
        # configuration is rolled back
        self.reverter.register_file_creation(False, ssl_fp)
        sift = False

        try:
            with open(avail_fp, "r") as orig_file:
                with open(ssl_fp, "w") as new_file:
                    new_file.write("<IfModule mod_ssl.c>\n")
                    for line in orig_file:
                        if self._sift_line(line):
                            if not sift:
                                new_file.write(
                                    "# Some rewrite rules in this file were "
                                    "were disabled on your HTTPS site,\n"
                                    "# because they have the potential to "
                                    "create redirection loops.\n")
                                sift = True
                            new_file.write("# " + line)
                        else:
                            new_file.write(line)
                    new_file.write("</IfModule>\n")
        except IOError:
            logger.fatal("Error writing/reading to file in make_vhost_ssl")
            raise errors.PluginError("Unable to write/read in make_vhost_ssl")

        if sift:
            reporter = zope.component.getUtility(interfaces.IReporter)
            reporter.add_message(
                "Some rewrite rules copied from {0} were disabled in the "
                "vhost for your HTTPS site located at {1} because they have "
                "the potential to create redirection loops.".format(avail_fp,
                                                                    ssl_fp),
                reporter.MEDIUM_PRIORITY)

    def _update_ssl_vhosts_addrs(self, vh_path):
        ssl_addrs = set()
        ssl_addr_p = self.aug.match(vh_path + "/arg")

        for addr in ssl_addr_p:
            old_addr = obj.Addr.fromstring(
                str(self.parser.get_arg(addr)))
            ssl_addr = old_addr.get_addr_obj("443")
            self.aug.set(addr, str(ssl_addr))
            ssl_addrs.add(ssl_addr)

        return ssl_addrs

    def _clean_vhost(self, vhost):
        # remove duplicated or conflicting ssl directives
        self._deduplicate_directives(vhost.path,
                                     ["SSLCertificateFile",
                                      "SSLCertificateKeyFile"])
        # remove all problematic directives
        self._remove_directives(vhost.path, ["SSLCertificateChainFile"])

    def _deduplicate_directives(self, vh_path, directives):
        for directive in directives:
            while len(self.parser.find_dir(directive, None,
                                           vh_path, False)) > 1:
                directive_path = self.parser.find_dir(directive, None,
                                                      vh_path, False)
                self.aug.remove(re.sub(r"/\w*$", "", directive_path[0]))

    def _remove_directives(self, vh_path, directives):
        for directive in directives:
            while len(self.parser.find_dir(directive, None,
                                           vh_path, False)) > 0:
                directive_path = self.parser.find_dir(directive, None,
                                                      vh_path, False)
                self.aug.remove(re.sub(r"/\w*$", "", directive_path[0]))

    def _add_dummy_ssl_directives(self, vh_path):
        self.parser.add_dir(vh_path, "SSLCertificateFile",
                            "insert_cert_file_path")
        self.parser.add_dir(vh_path, "SSLCertificateKeyFile",
                            "insert_key_file_path")
        self.parser.add_dir(vh_path, "Include", self.mod_ssl_conf)

    def _add_servername_alias(self, target_name, vhost):
        fp = vhost.filep
        vh_p = self.aug.match("/files%s//* [label()=~regexp('%s')]" %
                              (fp, parser.case_i("VirtualHost")))
        if not vh_p:
            return
        vh_path = vh_p[0]
        if (self.parser.find_dir("ServerName", target_name, start=vh_path, exclude=False)
           or self.parser.find_dir("ServerAlias", target_name, start=vh_path, exclude=False)):
            return
        if not self.parser.find_dir("ServerName", None, start=vh_path, exclude=False):
            self.parser.add_dir(vh_path, "ServerName", target_name)
        else:
            self.parser.add_dir(vh_path, "ServerAlias", target_name)
        self._add_servernames(vhost)

    def _add_name_vhost_if_necessary(self, vhost):
        """Add NameVirtualHost Directives if necessary for new vhost.

        NameVirtualHosts was a directive in Apache < 2.4
        https://httpd.apache.org/docs/2.2/mod/core.html#namevirtualhost

        :param vhost: New virtual host that was recently created.
        :type vhost: :class:`~letsencrypt_apache.obj.VirtualHost`

        """
        need_to_save = False

        # See if the exact address appears in any other vhost
        # Remember 1.1.1.1:* == 1.1.1.1 -> hence any()
        for addr in vhost.addrs:
            # In Apache 2.2, when a NameVirtualHost directive is not
            # set, "*" and "_default_" will conflict when sharing a port
            if addr.get_addr() in ("*", "_default_"):
                addrs = [obj.Addr((a, addr.get_port(),))
                         for a in ("*", "_default_")]

            for test_vh in self.vhosts:
                if (vhost.filep != test_vh.filep and
                        any(test_addr in addrs for
                            test_addr in test_vh.addrs) and
                        not self.is_name_vhost(addr)):
                    self.add_name_vhost(addr)
                    logger.info("Enabling NameVirtualHosts on %s", addr)
                    need_to_save = True

        if need_to_save:
            self.save()

    ######################################################################
    # Enhancements
    ######################################################################
    def supported_enhancements(self):  # pylint: disable=no-self-use
        """Returns currently supported enhancements."""
        return ["redirect", "ensure-http-header"]

    def enhance(self, domain, enhancement, options=None):
        """Enhance configuration.

        :param str domain: domain to enhance
        :param str enhancement: enhancement type defined in
            :const:`~letsencrypt.constants.ENHANCEMENTS`
        :param options: options for the enhancement
            See :const:`~letsencrypt.constants.ENHANCEMENTS`
            documentation for appropriate parameter.

        :raises .errors.PluginError: If Enhancement is not supported, or if
            there is any other problem with the enhancement.

        """
        try:
            func = self._enhance_func[enhancement]
        except KeyError:
            raise errors.PluginError(
                "Unsupported enhancement: {0}".format(enhancement))
        try:
            func(self.choose_vhost(domain), options)
        except errors.PluginError:
            logger.warn("Failed %s for %s", enhancement, domain)
            raise

    def _set_http_header(self, ssl_vhost, header_substring):
        """Enables header that is identified by header_substring on ssl_vhost.

        If the header identified by header_substring is not already set,
        a new Header directive is placed in ssl_vhost's configuration with
        arguments from: constants.HTTP_HEADER[header_substring]

        .. note:: This function saves the configuration

        :param ssl_vhost: Destination of traffic, an ssl enabled vhost
        :type ssl_vhost: :class:`~letsencrypt_apache.obj.VirtualHost`

        :param header_substring: string that uniquely identifies a header.
                e.g: Strict-Transport-Security, Upgrade-Insecure-Requests.
        :type str

        :returns: Success, general_vhost (HTTP vhost)
        :rtype: (bool, :class:`~letsencrypt_apache.obj.VirtualHost`)

        :raises .errors.PluginError: If no viable HTTP host can be created or
            set with header header_substring.

        """
        if "headers_module" not in self.parser.modules:
            self.enable_mod("headers")

        # Check if selected header is already set
        self._verify_no_matching_http_header(ssl_vhost, header_substring)

        # Add directives to server
        self.parser.add_dir(ssl_vhost.path, "Header",
                            constants.HEADER_ARGS[header_substring])

        self.save_notes += ("Adding %s header to ssl vhost in %s\n" %
                            (header_substring, ssl_vhost.filep))

        self.save()
        logger.info("Adding %s header to ssl vhost in %s", header_substring,
                    ssl_vhost.filep)

    def _verify_no_matching_http_header(self, ssl_vhost, header_substring):
        """Checks to see if an there is an existing Header directive that
        contains the string header_substring.

        :param ssl_vhost: vhost to check
        :type vhost: :class:`~letsencrypt_apache.obj.VirtualHost`

        :param header_substring: string that uniquely identifies a header.
                e.g: Strict-Transport-Security, Upgrade-Insecure-Requests.
        :type str

        :returns: boolean
        :rtype: (bool)

        :raises errors.PluginEnhancementAlreadyPresent When header
                header_substring exists

        """
        header_path = self.parser.find_dir("Header", None,
                                           start=ssl_vhost.path)
        if header_path:
            # "Existing Header directive for virtualhost"
            pat = '(?:[ "]|^)(%s)(?:[ "]|$)' % (header_substring.lower())
            for match in header_path:
                if re.search(pat, self.aug.get(match).lower()):
                    raise errors.PluginEnhancementAlreadyPresent(
                        "Existing %s header" % (header_substring))

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
        :type ssl_vhost: :class:`~letsencrypt_apache.obj.VirtualHost`

        :param unused_options: Not currently used
        :type unused_options: Not Available

        :returns: Success, general_vhost (HTTP vhost)
        :rtype: (bool, :class:`~letsencrypt_apache.obj.VirtualHost`)

        :raises .errors.PluginError: If no viable HTTP host can be created or
            used for the redirect.

        """
        if "rewrite_module" not in self.parser.modules:
            self.enable_mod("rewrite")
        general_vh = self._get_http_vhost(ssl_vhost)

        if general_vh is None:
            # Add virtual_server with redirect
            logger.debug("Did not find http version of ssl virtual host "
                         "attempting to create")
            redirect_addrs = self._get_proposed_addrs(ssl_vhost)
            for vhost in self.vhosts:
                if vhost.enabled and vhost.conflicts(redirect_addrs):
                    raise errors.PluginError(
                        "Unable to find corresponding HTTP vhost; "
                        "Unable to create one as intended addresses conflict; "
                        "Current configuration does not support automated "
                        "redirection")
            self._create_redirect_vhost(ssl_vhost)
        else:
            # Check if LetsEncrypt redirection already exists
            self._verify_no_letsencrypt_redirect(general_vh)

            # Note: if code flow gets here it means we didn't find the exact
            # letsencrypt RewriteRule config for redirection. Finding
            # another RewriteRule is likely to be fine in most or all cases,
            # but redirect loops are possible in very obscure cases; see #1620
            # for reasoning.
            if self._is_rewrite_exists(general_vh):
                logger.warn("Added an HTTP->HTTPS rewrite in addition to "
                            "other RewriteRules; you may wish to check for "
                            "overall consistency.")

            # Add directives to server
            # Note: These are not immediately searchable in sites-enabled
            #     even with save() and load()
            if not self._is_rewrite_engine_on(general_vh):
                self.parser.add_dir(general_vh.path, "RewriteEngine", "on")

            if self.get_version() >= (2, 3, 9):
                self.parser.add_dir(general_vh.path, "RewriteRule",
                                    constants.REWRITE_HTTPS_ARGS_WITH_END)
            else:
                self.parser.add_dir(general_vh.path, "RewriteRule",
                                    constants.REWRITE_HTTPS_ARGS)

            self.save_notes += ("Redirecting host in %s to ssl vhost in %s\n" %
                                (general_vh.filep, ssl_vhost.filep))
            self.save()

            logger.info("Redirecting vhost in %s to ssl vhost in %s",
                        general_vh.filep, ssl_vhost.filep)

    def _verify_no_letsencrypt_redirect(self, vhost):
        """Checks to see if a redirect was already installed by letsencrypt.

        Checks to see if virtualhost already contains a rewrite rule that is
        identical to Letsencrypt's redirection rewrite rule.

        :param vhost: vhost to check
        :type vhost: :class:`~letsencrypt_apache.obj.VirtualHost`

        :raises errors.PluginEnhancementAlreadyPresent: When the exact
                letsencrypt redirection WriteRule exists in virtual host.
        """
        rewrite_path = self.parser.find_dir(
            "RewriteRule", None, start=vhost.path)

        # There can be other RewriteRule directive lines in vhost config.
        # rewrite_args_dict keys are directive ids and the corresponding value
        # for each is a list of arguments to that directive.
        rewrite_args_dict = defaultdict(list)
        pat = r'.*(directive\[\d+\]).*'
        for match in rewrite_path:
            m = re.match(pat, match)
            if m:
                dir_id = m.group(1)
                rewrite_args_dict[dir_id].append(match)

        if rewrite_args_dict:
            redirect_args = [constants.REWRITE_HTTPS_ARGS,
                             constants.REWRITE_HTTPS_ARGS_WITH_END]

            for matches in rewrite_args_dict.values():
                if [self.aug.get(x) for x in matches] in redirect_args:
                    raise errors.PluginEnhancementAlreadyPresent(
                        "Let's Encrypt has already enabled redirection")

    def _is_rewrite_exists(self, vhost):
        """Checks if there exists a RewriteRule directive in vhost

        :param vhost: vhost to check
        :type vhost: :class:`~letsencrypt_apache.obj.VirtualHost`

        :returns: True if a RewriteRule directive exists.
        :rtype: bool

        """
        rewrite_path = self.parser.find_dir(
            "RewriteRule", None, start=vhost.path)
        return bool(rewrite_path)

    def _is_rewrite_engine_on(self, vhost):
        """Checks if a RewriteEngine directive is on

        :param vhost: vhost to check
        :type vhost: :class:`~letsencrypt_apache.obj.VirtualHost`

        """
        rewrite_engine_path = self.parser.find_dir("RewriteEngine", "on",
                                                   start=vhost.path)
        if rewrite_engine_path:
            return self.parser.get_arg(rewrite_engine_path[0])
        return False

    def _create_redirect_vhost(self, ssl_vhost):
        """Creates an http_vhost specifically to redirect for the ssl_vhost.

        :param ssl_vhost: ssl vhost
        :type ssl_vhost: :class:`~letsencrypt_apache.obj.VirtualHost`

        :returns: tuple of the form
            (`success`, :class:`~letsencrypt_apache.obj.VirtualHost`)
        :rtype: tuple

        """
        text = self._get_redirect_config_str(ssl_vhost)

        redirect_filepath = self._write_out_redirect(ssl_vhost, text)

        self.aug.load()
        # Make a new vhost data structure and add it to the lists
        new_vhost = self._create_vhost(parser.get_aug_path(redirect_filepath))
        self.vhosts.append(new_vhost)

        # Finally create documentation for the change
        self.save_notes += ("Created a port 80 vhost, %s, for redirection to "
                            "ssl vhost %s\n" %
                            (new_vhost.filep, ssl_vhost.filep))

    def _get_redirect_config_str(self, ssl_vhost):
        # get servernames and serveraliases
        serveralias = ""
        servername = ""

        if ssl_vhost.name is not None:
            servername = "ServerName " + ssl_vhost.name
        if ssl_vhost.aliases:
            serveralias = "ServerAlias " + " ".join(ssl_vhost.aliases)

        rewrite_rule_args = []
        if self.get_version() >= (2, 3, 9):
            rewrite_rule_args = constants.REWRITE_HTTPS_ARGS_WITH_END
        else:
            rewrite_rule_args = constants.REWRITE_HTTPS_ARGS

        return ("<VirtualHost %s>\n"
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
                % (" ".join(str(addr) for
                            addr in self._get_proposed_addrs(ssl_vhost)),
                   servername, serveralias,
                   " ".join(rewrite_rule_args)))

    def _write_out_redirect(self, ssl_vhost, text):
        # This is the default name
        redirect_filename = "le-redirect.conf"

        # See if a more appropriate name can be applied
        if ssl_vhost.name is not None:
            # make sure servername doesn't exceed filename length restriction
            if len(ssl_vhost.name) < (255 - (len(redirect_filename) + 1)):
                redirect_filename = "le-redirect-%s.conf" % ssl_vhost.name

        redirect_filepath = os.path.join(self.conf("vhost-root"),
                                         redirect_filename)

        # Register the new file that will be created
        # Note: always register the creation before writing to ensure file will
        # be removed in case of unexpected program exit
        self.reverter.register_file_creation(False, redirect_filepath)

        # Write out file
        with open(redirect_filepath, "w") as redirect_file:
            redirect_file.write(text)
        logger.info("Created redirect file: %s", redirect_filename)

        return redirect_filepath

    def _get_http_vhost(self, ssl_vhost):
        """Find appropriate HTTP vhost for ssl_vhost."""
        # First candidate vhosts filter
        candidate_http_vhs = [
            vhost for vhost in self.vhosts if not vhost.ssl
        ]

        # Second filter - check addresses
        for http_vh in candidate_http_vhs:
            if http_vh.same_server(ssl_vhost):
                return http_vh

        return None

    def _get_proposed_addrs(self, vhost, port="80"):
        """Return all addrs of vhost with the port replaced with the specified.

        :param obj.VirtualHost ssl_vhost: Original Vhost
        :param str port: Desired port for new addresses

        :returns: `set` of :class:`~obj.Addr`

        """
        redirects = set()
        for addr in vhost.addrs:
            redirects.add(addr.get_addr_obj(port))

        return redirects

    def get_all_certs_keys(self):
        """Find all existing keys, certs from configuration.

        Retrieve all certs and keys set in VirtualHosts on the Apache server

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
                    "SSLCertificateFile", None,
                    start=vhost.path, exclude=False)
                key_path = self.parser.find_dir(
                    "SSLCertificateKeyFile", None,
                    start=vhost.path, exclude=False)

                if cert_path and key_path:
                    cert = os.path.abspath(self.parser.get_arg(cert_path[-1]))
                    key = os.path.abspath(self.parser.get_arg(key_path[-1]))
                    c_k.add((cert, key, get_file_path(cert_path[-1])))
                else:
                    logger.warning(
                        "Invalid VirtualHost configuration - %s", vhost.filep)
        return c_k

    def is_site_enabled(self, avail_fp):
        """Checks to see if the given site is enabled.

        .. todo:: fix hardcoded sites-enabled, check os.path.samefile

        :param str avail_fp: Complete file path of available site

        :returns: Success
        :rtype: bool

        """

        enabled_dir = os.path.join(self.parser.root, "sites-enabled")
        if not os.path.isdir(enabled_dir):
            error_msg = ("Directory '{0}' does not exist. Please ensure "
                         "that the values for --apache-handle-sites and "
                         "--apache-server-root are correct for your "
                         "environment.".format(enabled_dir))
            raise errors.ConfigurationError(error_msg)
        for entry in os.listdir(enabled_dir):
            try:
                if filecmp.cmp(avail_fp, os.path.join(enabled_dir, entry)):
                    return True
            except OSError:
                pass
        return False

    def enable_site(self, vhost):
        """Enables an available site, Apache reload required.

        .. note:: Does not make sure that the site correctly works or that all
                  modules are enabled appropriately.

        .. todo:: This function should number subdomains before the domain
                  vhost

        .. todo:: Make sure link is not broken...

        :param vhost: vhost to enable
        :type vhost: :class:`~letsencrypt_apache.obj.VirtualHost`

        :raises .errors.NotSupportedError: If filesystem layout is not
            supported.

        """
        if self.is_site_enabled(vhost.filep):
            return

        if "/sites-available/" in vhost.filep:
            enabled_path = ("%s/sites-enabled/%s" %
                            (self.parser.root, os.path.basename(vhost.filep)))
            self.reverter.register_file_creation(False, enabled_path)
            os.symlink(vhost.filep, enabled_path)
            vhost.enabled = True
            logger.info("Enabling available site: %s", vhost.filep)
            self.save_notes += "Enabled site %s\n" % vhost.filep
        else:
            raise errors.NotSupportedError(
                "Unsupported filesystem layout. "
                "sites-available/enabled expected.")

    def enable_mod(self, mod_name, temp=False):
        """Enables module in Apache.

        Both enables and reloads Apache so module is active.

        :param str mod_name: Name of the module to enable. (e.g. 'ssl')
        :param bool temp: Whether or not this is a temporary action.

        :raises .errors.NotSupportedError: If the filesystem layout is not
            supported.
        :raises .errors.MisconfigurationError: If a2enmod or a2dismod cannot be
            run.

        """
        # Support Debian specific setup
        avail_path = os.path.join(self.parser.root, "mods-available")
        enabled_path = os.path.join(self.parser.root, "mods-enabled")
        if not os.path.isdir(avail_path) or not os.path.isdir(enabled_path):
            raise errors.NotSupportedError(
                "Unsupported directory layout. You may try to enable mod %s "
                "and try again." % mod_name)

        deps = _get_mod_deps(mod_name)

        # Enable all dependencies
        for dep in deps:
            if (dep + "_module") not in self.parser.modules:
                self._enable_mod_debian(dep, temp)
                self._add_parser_mod(dep)

                note = "Enabled dependency of %s module - %s" % (mod_name, dep)
                if not temp:
                    self.save_notes += note + os.linesep
                logger.debug(note)

        # Enable actual module
        self._enable_mod_debian(mod_name, temp)
        self._add_parser_mod(mod_name)

        if not temp:
            self.save_notes += "Enabled %s module in Apache\n" % mod_name
        logger.info("Enabled Apache %s module", mod_name)

        # Modules can enable additional config files. Variables may be defined
        # within these new configuration sections.
        # Reload is not necessary as DUMP_RUN_CFG uses latest config.
        self.parser.update_runtime_variables()

    def _add_parser_mod(self, mod_name):
        """Shortcut for updating parser modules."""
        self.parser.modules.add(mod_name + "_module")
        self.parser.modules.add("mod_" + mod_name + ".c")

    def _enable_mod_debian(self, mod_name, temp):
        """Assumes mods-available, mods-enabled layout."""
        # Generate reversal command.
        # Try to be safe here... check that we can probably reverse before
        # applying enmod command
        if not le_util.exe_exists(self.conf("dismod")):
            raise errors.MisconfigurationError(
                "Unable to find a2dismod, please make sure a2enmod and "
                "a2dismod are configured correctly for letsencrypt.")

        self.reverter.register_undo_command(
            temp, [self.conf("dismod"), mod_name])
        le_util.run_script([self.conf("enmod"), mod_name])

    def restart(self):
        """Runs a config test and reloads the Apache server.

        :raises .errors.MisconfigurationError: If either the config test
            or reload fails.

        """
        self.config_test()
        logger.debug(self.reverter.view_config_changes(for_logging=True))
        self._reload()

    def _reload(self):
        """Reloads the Apache server.

        :raises .errors.MisconfigurationError: If reload fails

        """
        try:
            le_util.run_script(constants.os_constant("restart_cmd"))
        except errors.SubprocessError as err:
            raise errors.MisconfigurationError(str(err))

    def config_test(self):  # pylint: disable=no-self-use
        """Check the configuration of Apache for errors.

        :raises .errors.MisconfigurationError: If config_test fails

        """
        try:
            le_util.run_script(constants.os_constant("conftest_cmd"))
        except errors.SubprocessError as err:
            raise errors.MisconfigurationError(str(err))

    def get_version(self):
        """Return version of Apache Server.

        Version is returned as tuple. (ie. 2.4.7 = (2, 4, 7))

        :returns: version
        :rtype: tuple

        :raises .PluginError: if unable to find Apache version

        """
        try:
            stdout, _ = le_util.run_script(
                constants.os_constant("version_cmd"))
        except errors.SubprocessError:
            raise errors.PluginError(
                "Unable to run %s -v" %
                constants.os_constant("version_cmd"))

        regex = re.compile(r"Apache/([0-9\.]*)", re.IGNORECASE)
        matches = regex.findall(stdout)

        if len(matches) != 1:
            raise errors.PluginError("Unable to find Apache version")

        return tuple([int(i) for i in matches[0].split(".")])

    def more_info(self):
        """Human-readable string to help understand the module"""
        return (
            "Configures Apache to authenticate and install HTTPS.{0}"
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
        return [challenges.TLSSNI01]

    def perform(self, achalls):
        """Perform the configuration related challenge.

        This function currently assumes all challenges will be fulfilled.
        If this turns out not to be the case in the future. Cleanup and
        outstanding challenges will have to be designed better.

        """
        self._chall_out.update(achalls)
        responses = [None] * len(achalls)
        chall_doer = tls_sni_01.ApacheTlsSni01(self)

        for i, achall in enumerate(achalls):
            # Currently also have chall_doer hold associated index of the
            # challenge. This helps to put all of the responses back together
            # when they are all complete.
            chall_doer.add_chall(achall, i)

        sni_response = chall_doer.perform()
        if sni_response:
            # Must reload in order to activate the challenges.
            # Handled here because we may be able to load up other challenge
            # types
            self.restart()

            # TODO: Remove this dirty hack. We need to determine a reliable way
            # of identifying when the new configuration is being used.
            time.sleep(3)

            # Go through all of the challenges and assign them to the proper
            # place in the responses return value. All responses must be in the
            # same order as the original challenges.
            for i, resp in enumerate(sni_response):
                responses[chall_doer.indices[i]] = resp

        return responses

    def cleanup(self, achalls):
        """Revert all challenges."""
        self._chall_out.difference_update(achalls)

        # If all of the challenges have been finished, clean up everything
        if not self._chall_out:
            self.revert_challenge_config()
            self.restart()
            self.parser.init_modules()


def _get_mod_deps(mod_name):
    """Get known module dependencies.

    .. note:: This does not need to be accurate in order for the client to
        run.  This simply keeps things clean if the user decides to revert
        changes.
    .. warning:: If all deps are not included, it may cause incorrect parsing
        behavior, due to enable_mod's shortcut for updating the parser's
        currently defined modules (`.ApacheConfigurator._add_parser_mod`)
        This would only present a major problem in extremely atypical
        configs that use ifmod for the missing deps.

    """
    deps = {
        "ssl": ["setenvif", "mime"]
    }
    return deps.get(mod_name, [])


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
        # Cast all to lowercase to be case insensitive
        find_if = avail_fp.lower().find("/ifmodule")
        if find_if != -1:
            avail_fp = avail_fp[:find_if]
            continue
        find_vh = avail_fp.lower().find("/virtualhost")
        if find_vh != -1:
            avail_fp = avail_fp[:find_vh]
            continue
        find_macro = avail_fp.lower().find("/macro")
        if find_macro != -1:
            avail_fp = avail_fp[:find_macro]
            continue
        break
    return avail_fp


def install_ssl_options_conf(options_ssl):
    """
    Copy Let's Encrypt's SSL options file into the system's config dir if
    required.
    """
    # XXX if we ever try to enforce a local privilege boundary (eg, running
    # letsencrypt for unprivileged users via setuid), this function will need
    # to be modified.

    # XXX if the user is in security-autoupdate mode, we should be willing to
    # overwrite the options_ssl file at least if it's unmodified:
    # https://github.com/letsencrypt/letsencrypt/issues/1123

    # Check to make sure options-ssl.conf is installed
    if not os.path.isfile(options_ssl):
        shutil.copyfile(constants.os_constant("MOD_SSL_CONF_SRC"), options_ssl)
