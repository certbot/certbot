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
                    (self.tup[0] == other.tup[0]
                     and self.is_wildcard() and other.is_wildcard()))
        return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def is_wildcard(self):
        """Returns if address has a wildcard port."""
        return self.tup[1] == "*" or not self.tup[1]

    def get_sni_addr(self, port):
        """Returns the least specific address that resolves on the port.

        Example:
        1.2.3.4:443 -> 1.2.3.4:<port>
        1.2.3.4:* -> 1.2.3.4:*

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

    .. todo:: Handle ServerNames appropriately...

    """
    # ?: is used for not returning enclosed characters
    strip_name = re.compile(r"^(?:.+://)?([^ :$]*)")

    def __init__(self, filep, path, addrs, ssl, enabled, name=None, aliases=[]):
        # pylint: disable=too-many-arguments
        """Initialize a VH."""
        self.filep = filep
        self.path = path
        self.addrs = addrs
        self.name = name
        self.aliases = aliases
        self.ssl = ssl
        self.enabled = enabled

    def add_names(self, servername, serveralias):
        """Add name to vhost."""
        self.name = servername
        self.aliases = serveralias

    def get_names(self):
        all_names = set(self.aliases)
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
            "Site Enabled: {active}".format(
                filename=self.filep,
                vhpath=self.path,
                addrs=", ".join(str(addr) for addr in self.addrs),
                name=self.name if self.name is not None else "",
                aliases=", ".join(name for name in self.aliases),
                tls="Yes" if self.ssl else "No",
                active="Yes" if self.enabled else "No"))

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return (self.filep == other.filep and self.path == other.path and
                    self.addrs == other.addrs and
                    self.get_names() == other.get_names() and
                    self.ssl == other.ssl and self.enabled == other.enabled)

        return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def conflicts(self, addrs):
        """See if vhost conflicts with any of the addrs.

        This determines whether or not these addresses would/could overwrite
        the vhost addresses.

        :param addrs: Iterable Addresses
        :type addrs: Iterable :class:~obj.Addr

        :returns: If addresses conflict with vhost
        :rtype: bool

        """
        # TODO: Handle domain name addrs...
        for addr in addrs:
            if (addr in self.addrs or addr.get_addr_obj("") in self.addrs or
                    addr.get_addr_obj("*") in self.addrs):
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
        if self.name is not None:
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
                    # e.g. 127.0.0.1:*
                    already_found.add(local_addr.get_addr())
                    break
            else:
                return False

        return True