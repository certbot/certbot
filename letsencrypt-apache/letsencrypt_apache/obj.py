"""Module contains classes used by the Apache Configurator."""
import re

from letsencrypt.plugins import common


class Addr(common.Addr):
    """Represents an Apache address."""
    def __eq__(self, other):
        """This is defined as equalivalent within Apache.

        ip_addr:* == ip_addr

        """
        if isinstance(other, self.__class__):
            return ((self.tup == other.tup) or
                    (self.tup[0] == other.tup[0] and
                     self.is_wildcard() and other.is_wildcard()))
        return False

    def __ne__(self, other):
        return not self.__eq__(other)

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
        else:
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


class VirtualHost(object):  # pylint: disable=too-few-public-methods
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

    https://httpd.apache.org/docs/2.4/vhosts/details.html

    .. todo:: Any vhost that includes the magic _default_ wildcard is given the
              same ServerName as the main server.

    """
    # ?: is used for not returning enclosed characters
    strip_name = re.compile(r"^(?:.+://)?([^ :$]*)")

    def __init__(self, filep, path, addrs, ssl, enabled, name=None,
                 aliases=None, modmacro=False):

        # pylint: disable=too-many-arguments
        """Initialize a VH."""
        self.filep = filep
        self.path = path
        self.addrs = addrs
        self.name = name
        self.aliases = aliases if aliases is not None else set()
        self.ssl = ssl
        self.enabled = enabled
        self.modmacro = modmacro

    def get_names(self):
        """Return a set of all names."""
        all_names = set()
        all_names.update(self.aliases)
        # Strip out any scheme:// and <port> field from servername
        if self.name is not None:
            all_names.add(VirtualHost.strip_name.findall(self.name)[0])

        return all_names

    def __str__(self):
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

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return (self.filep == other.filep and self.path == other.path and
                    self.addrs == other.addrs and
                    self.get_names() == other.get_names() and
                    self.ssl == other.ssl and
                    self.enabled == other.enabled and
                    self.modmacro == other.modmacro)

        return False

    def __ne__(self, other):
        return not self.__eq__(other)

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

    def same_server(self, vhost):
        """Determines if the vhost is the same 'server'.

        Used in redirection - indicates whether or not the two virtual hosts
        serve on the exact same IP combinations, but different ports.

        .. todo:: Handle _default_

        """

        if vhost.get_names() != self.get_names():
            return False

        # If equal and set is not empty... assume same server
        if self.name is not None or self.aliases:
            return True

        # Both sets of names are empty.

        # Make conservative educated guess... this is very restrictive
        # Consider adding more safety checks.
        if len(vhost.addrs) != len(self.addrs):
            return False

        # already_found acts to keep everything very conservative.
        # Don't allow multiple ip:ports in same set.
        already_found = set()

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
