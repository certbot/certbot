"""Module contains classes used by the Apache Configurator."""


class VirtualHost(object):  # pylint: disable=too-few-public-methods
    """Represents an Apache Virtualhost.

    :ivar str filep: file path of VH
    :ivar str path: Augeas path to virtual host
    :ivar set addrs: Virtual Host addresses (:class:`set` of
        :class:`common.Addr`)
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
        return ("File: %s\n"
                "Vhost path: %s\n"
                "Addresses: %s\n"
                "Names: %s\n"
                "TLS: %s\n"
                "Enabled: %s" % (self.filep, self.path, addr_str,
                                 self.names, self.ssl, self.enabled))

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return (self.filep == other.filep and self.path == other.path and
                    self.addrs == other.addrs and
                    self.names == other.names and
                    self.ssl == other.ssl and self.enabled == other.enabled)

        return False
