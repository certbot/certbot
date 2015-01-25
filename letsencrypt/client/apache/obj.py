"""Module contains classes used by the Apache Configurator."""


class Addr(object):
    r"""Represents an Apache VirtualHost address.

    :param str addr: addr part of vhost address
    :param str port: port number or \*, or ""

    """
    def __init__(self, tup):
        self.tup = tup

    @classmethod
    def fromstring(cls, str_addr):
        """Initialize Addr from string."""
        tup = str_addr.partition(':')
        return cls((tup[0], tup[2]))

    def __str__(self):
        if self.tup[1]:
            return "%s:%s" % self.tup
        return self.tup[0]

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.tup == other.tup
        return False

    def __hash__(self):
        return hash(self.tup)

    def get_addr(self):
        """Return addr part of Addr object."""
        return self.tup[0]

    def get_port(self):
        """Return port."""
        return self.tup[1]

    def get_addr_obj(self, port):
        """Return new address object with same addr and new port."""
        return self.__class__((self.tup[0], port))


class VirtualHost(object):  # pylint: disable=too-few-public-methods
    """Represents an Apache Virtualhost.

    :ivar str filep: file path of VH
    :ivar str path: Augeas path to virtual host
    :ivar set addrs: Virtual Host addresses (:class:`set` of :class:`Addr`)
    :ivar set names: Server names/aliases of vhost
        (:class:`list` of :class:`str`)

    :ivar bool ssl: SSLEngine on in vhost
    :ivar bool enabled: Virtual host is enabled

    """

    def __init__(self, filep, path, addrs, ssl, enabled, names=None):
        # pylint: disable=too-many-arguments
        """Initialize a VH."""
        self.filep = filep
        self.path = path
        self.addrs = addrs
        self.names = set() if names is None else set(names)
        self.ssl = ssl
        self.enabled = enabled

    def add_name(self, name):
        """Add name to vhost."""
        self.names.add(name)

    def __str__(self):
        addr_str = ", ".join(str(addr) for addr in self.addrs)
        return ("file: %s\n"
                "vh_path: %s\n"
                "addrs: %s\n"
                "names: %s\n"
                "ssl: %s\n"
                "enabled: %s" % (self.filep, self.path, addr_str,
                                 self.names, self.ssl, self.enabled))

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return (self.filep == other.filep and self.path == other.path and
                    self.addrs == other.addrs and
                    self.names == other.names and
                    self.ssl == other.ssl and self.enabled == other.enabled)

        return False
