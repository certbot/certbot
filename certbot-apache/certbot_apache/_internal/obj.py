"""Module contains classes used by the Apache Configurator."""
import re
from typing import Set

from certbot.plugins import common


class Addr(common.Addr):
    """Represents an Apache address."""

    def __eq__(self, other):
        """This is defined as equivalent within Apache.

        ip_addr:* == ip_addr

        """
        if isinstance(other, self.__class__):
            return ((self.tup == other.tup) or
                    (self.tup[0] == other.tup[0] and
                     self.is_wildcard() and other.is_wildcard()))
        return False

    def __repr__(self):
        return "certbot_apache._internal.obj.Addr(" + repr(self.tup) + ")"

    def __hash__(self):  # pylint: disable=useless-super-delegation
        # Python 3 requires explicit overridden for __hash__ if __eq__ or
        # __cmp__ is overridden. See https://bugs.python.org/issue2235
        return super().__hash__()

    def _addr_less_specific(self, addr):
        """Returns if addr.get_addr() is more specific than self.get_addr()."""
        # pylint: disable=protected-access
        return addr._rank_specific_addr() > self._rank_specific_addr()

    def _rank_specific_addr(self):
        """Returns numerical rank for get_addr()

        :returns: 2 - FQ, 1 - wildcard, 0 - _default_
        :rtype: int

        """
        if self.get_addr() == "_default_":
            return 0
        elif self.get_addr() == "*":
            return 1
        return 2

    def conflicts(self, addr):
        r"""Returns if address could conflict with correct function of self.

        Could addr take away service provided by self within Apache?

        .. note::IP Address is more important than wildcard.
            Connection from 127.0.0.1:80 with choices of *:80 and 127.0.0.1:*
            chooses 127.0.0.1:\*

        .. todo:: Handle domain name addrs...

        Examples:

        =========================================  =====
        ``127.0.0.1:\*.conflicts(127.0.0.1:443)``  True
        ``127.0.0.1:443.conflicts(127.0.0.1:\*)``  False
        ``\*:443.conflicts(\*:80)``                False
        ``_default_:443.conflicts(\*:443)``        True
        =========================================  =====

        """
        if self._addr_less_specific(addr):
            return True
        elif self.get_addr() == addr.get_addr():
            if self.is_wildcard() or self.get_port() == addr.get_port():
                return True
        return False

    def is_wildcard(self):
        """Returns if address has a wildcard port."""
        return self.tup[1] == "*" or not self.tup[1]

    def get_sni_addr(self, port):
        """Returns the least specific address that resolves on the port.

        Examples:

        - ``1.2.3.4:443`` -> ``1.2.3.4:<port>``
        - ``1.2.3.4:*`` -> ``1.2.3.4:*``

        :param str port: Desired port

        """
        if self.is_wildcard():
            return self

        return self.get_addr_obj(port)


class VirtualHost:
    """Represents an Apache Virtualhost.

    :ivar str filep: file path of VH
    :ivar str path: Augeas path to virtual host
    :ivar set addrs: Virtual Host addresses (:class:`set` of
        :class:`common.Addr`)
    :ivar str name: ServerName of VHost
    :ivar list aliases: Server aliases of vhost
        (:class:`list` of :class:`str`)

    :ivar bool ssl: SSLEngine on in vhost
    :ivar bool enabled: Virtual host is enabled
    :ivar bool modmacro: VirtualHost is using mod_macro
    :ivar VirtualHost ancestor: A non-SSL VirtualHost this is based on

    https://httpd.apache.org/docs/2.4/vhosts/details.html

    .. todo:: Any vhost that includes the magic _default_ wildcard is given the
              same ServerName as the main server.

    """
    # ?: is used for not returning enclosed characters
    strip_name = re.compile(r"^(?:.+://)?([^ :$]*)")

    def __init__(self, filep, path, addrs, ssl, enabled, name=None,
                 aliases=None, modmacro=False, ancestor=None, node=None):

        """Initialize a VH."""
        self.filep = filep
        self.path = path
        self.addrs = addrs
        self.name = name
        self.aliases = aliases if aliases is not None else set()
        self.ssl = ssl
        self.enabled = enabled
        self.modmacro = modmacro
        self.ancestor = ancestor
        self.node = node

    def get_names(self):
        """Return a set of all names."""
        all_names: Set[str] = set()
        all_names.update(self.aliases)
        # Strip out any scheme:// and <port> field from servername
        if self.name is not None:
            all_names.add(VirtualHost.strip_name.findall(self.name)[0])

        return all_names

    def __str__(self):
        """
        Returns a string representation of the specified vhost, including its file path,
        addresses (if any), names and TLS status.

        :param vhost: The vhost to
        get information from.
        :type vhpath: :class:`~certbot_apache._internal.obj.VirtualHost`

        :returns: A string representation of the specified VH object,
        or "None" if no VH is provided..
        """
        return (
            "File: {filename}\n"
            "Vhost path: {vhpath}\n"
            "Addresses: {addrs}\n"
            "Name: {name}\n"
            "Aliases: {aliases}\n"
            "TLS Enabled: {tls}\n"
            "Site Enabled: {active}\n"
            "mod_macro Vhost: {modmacro}".format(
                filename=self.filep,
                vhpath=self.path,
                addrs=", ".join(str(addr) for addr in self.addrs),
                name=self.name if self.name is not None else "",
                aliases=", ".join(name for name in self.aliases),
                tls="Yes" if self.ssl else "No",
                active="Yes" if self.enabled else "No",
                modmacro="Yes" if self.modmacro else "No"))

    def display_repr(self):
        """Return a representation of VHost to be used in dialog"""
        return (
            "File: {filename}\n"
            "Addresses: {addrs}\n"
            "Names: {names}\n"
            "HTTPS: {https}\n".format(
                filename=self.filep,
                addrs=", ".join(str(addr) for addr in self.addrs),
                names=", ".join(self.get_names()),
                https="Yes" if self.ssl else "No"))

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return (self.filep == other.filep and self.path == other.path and
                    self.addrs == other.addrs and
                    self.get_names() == other.get_names() and
                    self.ssl == other.ssl and
                    self.enabled == other.enabled and
                    self.modmacro == other.modmacro)

        return False

    def __hash__(self):
        """
        :param filep: The full path to the file that contains this VirtualHost
        :param path: The context of the VirtualHost (ie. /, /some/dir, etc.)
        :param
        addrs: A list of server IP addresses or FQDNs for this vhost.
                      This *may* contain wildcards at the zeroth element in case a non-IP is
        specified as first argument to ``add_ip_list``.  See :func`~add_ip_list`.
                       If no IPs are present in this list then all IPs assigned to
        this machine are assumed by default.  This means that if you want a particular vhost to be available only on one interface but available via both
        interfaces then you must specify only one address here and not ``get_virtualhost`` will return None unless it finds an exact match for your domain
        name and port number combination across all interfaces rather than just your intended interface.  In other words, if you have multiple interfaces
        configured with static addresses then do not use any wildcard entries here because get_virtualhost will find a match on these entries across all
        interfaces rather than just your intended interface resulting in None being returned instead of the correct virtual host entry object
        """
        """
        :param filep: A string containing the full path of the configuration file
                      (e.g. ``/etc/apache2/apache2.conf``) that this line belongs to
        :param path: A string containing the directive's path (e.g. ``Listen``, or ``NameVirtualHost``)
                     This is also used as variable name in
        :py:meth`get_names`.
                     If it contains a space, it will be replaced by an underscore '_' character; e.g.:

                       * Listen 8080
        becomes Listen_8080

                     This makes it possible to use :py:meth`get_names` for finding all directives with a specific name, without needing
        complex regular expressions; e.g.:

                       * get_names('Listen') returns ['Listen', 'Listen 443', ...]

                       *
        get_names('NameVirtualHost') returns ['NameVirtualHost', ...] and not only those that have "name" in their paths like most other directives do!  #
        noqadocskip
                addrs = An array of strings representing IP addresses where this directive can be found ("[ip1|host1 ip2|host2]" syntax
        """
        return hash((self.filep, self.path,
                     tuple(self.addrs), tuple(self.get_names()),
                     self.ssl, self.enabled, self.modmacro))

    def conflicts(self, addrs):
        """See if vhost conflicts with any of the addrs.

        This determines whether or not these addresses would/could overwrite
        the vhost addresses.

        :param addrs: Iterable Addresses
        :type addrs: Iterable :class:~obj.Addr

        :returns: If addresses conflicts with vhost
        :rtype: bool

        """
        for pot_addr in addrs:
            for addr in self.addrs:
                if addr.conflicts(pot_addr):
                    return True
        return False

    def same_server(self, vhost, generic=False):
        """Determines if the vhost is the same 'server'.

        Used in redirection - indicates whether or not the two virtual hosts
        serve on the exact same IP combinations, but different ports.
        The generic flag indicates that that we're trying to match to a
        default or generic vhost

        .. todo:: Handle _default_

        """

        if not generic:
            if vhost.get_names() != self.get_names():
                return False

            # If equal and set is not empty... assume same server
            if self.name is not None or self.aliases:
                return True
        # If we're looking for a generic vhost,
        # don't return one with a ServerName
        elif self.name:
            return False

        # Both sets of names are empty.

        # Make conservative educated guess... this is very restrictive
        # Consider adding more safety checks.
        if len(vhost.addrs) != len(self.addrs):
            return False

        # already_found acts to keep everything very conservative.
        # Don't allow multiple ip:ports in same set.
        already_found: Set[str] = set()

        for addr in vhost.addrs:
            for local_addr in self.addrs:
                if (local_addr.get_addr() == addr.get_addr() and
                        local_addr != addr and
                        local_addr.get_addr() not in already_found):

                    # This intends to make sure we aren't double counting...
                    # e.g. 127.0.0.1:* - We require same number of addrs
                    #  currently
                    already_found.add(local_addr.get_addr())
                    break
            else:
                return False

        return True
