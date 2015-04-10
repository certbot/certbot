"""Module contains classes used by the Nginx Configurator."""
import re


class Addr(object):
    """Represents an Nginx address, i.e. what comes after the 'listen'
    directive.

    According to http://nginx.org/en/docs/http/ngx_http_core_module.html#listen,
    this may be address[:port], port, or unix:path. The latter is ignored here.

    The default value if no directive is specified is *:80 (superuser) or
    *:8000 (otherwise). If no port is specified, the default is 80. If no
    address is specified, listen on all addresses.

    .. todo:: Old-style nginx configs define SSL vhosts in a separate block
    instead of using 'ssl' in the listen directive

    :param str addr: addr part of vhost address, may be hostname, IPv4, IPv6,
        "", or "*"
    :param str port: port number or "*" or ""
    :param bool ssl: Whether the directive includes 'ssl'
    :param bool default: Whether the directive includes 'default_server'

    """
    def __init__(self, host, port, ssl, default):
        self.tup = (host, port)
        self.ssl = ssl
        self.default = default

    @classmethod
    def fromstring(cls, str_addr):
        """Initialize Addr from string."""
        parts = str_addr.split(' ')
        ssl = False
        default = False
        host = ''
        port = ''

        # The first part must be the address
        addr = parts.pop(0)

        # Ignore UNIX-domain sockets
        if addr.startswith('unix:'):
            return None

        tup = addr.partition(':')
        if re.match('^\d+$', tup[0]):
            # This is a bare port, not a hostname. E.g. listen 80
            host = ''
            port = tup[0]
        else:
            # This is a host-port tuple. E.g. listen 127.0.0.1:*
            host = tup[0]
            port = tup[2]

        # The rest of the parts are options; we only care about ssl and default
        while len(parts) > 0:
            nextpart = parts.pop()
            if nextpart == 'ssl':
                ssl = True
            elif nextpart == 'default_server':
                default = True

        return cls(host, port, ssl, default)

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
    """Represents an Nginx Virtualhost.

    :ivar str filep: file path of VH
    :ivar set addrs: Virtual Host addresses (:class:`set` of :class:`Addr`)
    :ivar set names: Server names/aliases of vhost
        (:class:`list` of :class:`str`)

    :ivar bool ssl: SSLEngine on in vhost
    :ivar bool enabled: Virtual host is enabled

    """

    def __init__(self, filep, addrs, ssl, enabled, names):
        # pylint: disable=too-many-arguments
        """Initialize a VH."""
        self.filep = filep
        self.addrs = addrs
        self.names = names
        self.ssl = ssl
        self.enabled = enabled

    def __str__(self):
        addr_str = ", ".join(str(addr) for addr in self.addrs)
        return ("file: %s\n"
                "addrs: %s\n"
                "names: %s\n"
                "ssl: %s\n"
                "enabled: %s" % (self.filep, addr_str,
                                 self.names, self.ssl, self.enabled))

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return (self.filep == other.filep and
                    self.addrs == other.addrs and
                    self.names == other.names and
                    self.ssl == other.ssl and self.enabled == other.enabled)

        return False
