"""Module contains classes used by the Nginx Configurator."""
import re

from certbot.plugins import common


class Addr(common.Addr):
    r"""Represents an Nginx address, i.e. what comes after the 'listen'
    directive.

    According to the `documentation`_, this may be address[:port], port,
    or unix:path. The latter is ignored here.

    The default value if no directive is specified is \*:80 (superuser)
    or \*:8000 (otherwise). If no port is specified, the default is
    80. If no address is specified, listen on all addresses.

    .. _documentation:
       http://nginx.org/en/docs/http/ngx_http_core_module.html#listen

    .. todo:: Old-style nginx configs define SSL vhosts in a separate
              block instead of using 'ssl' in the listen directive.

    :param str addr: addr part of vhost address, may be hostname, IPv4, IPv6,
        "", or "\*"
    :param str port: port number or "\*" or ""
    :param bool ssl: Whether the directive includes 'ssl'
    :param bool default: Whether the directive includes 'default_server'

    """
    def __init__(self, host, port, ssl, default):
        super(Addr, self).__init__((host, port))
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
        if re.match(r'^\d+$', tup[0]):
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
        parts = ''
        if self.tup[0] and self.tup[1]:
            parts = "%s:%s" % self.tup
        elif self.tup[0]:
            parts = self.tup[0]
        else:
            parts = self.tup[1]

        if self.default:
            parts += ' default_server'
        if self.ssl:
            parts += ' ssl'

        return parts

    def __repr__(self):
        return "Addr(" + self.__str__() + ")"

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return (self.tup == other.tup and
                    self.ssl == other.ssl and
                    self.default == other.default)
        return False


class VirtualHost(object):  # pylint: disable=too-few-public-methods
    """Represents an Nginx Virtualhost.

    :ivar str filep: file path of VH
    :ivar set addrs: Virtual Host addresses (:class:`set` of :class:`Addr`)
    :ivar set names: Server names/aliases of vhost
        (:class:`list` of :class:`str`)
    :ivar list raw: The raw form of the parsed server block

    :ivar bool ssl: SSLEngine on in vhost
    :ivar bool enabled: Virtual host is enabled
    :ivar list path: The indices into the parsed file used to access
        the server block defining the vhost

    """

    def __init__(self, filep, addrs, ssl, enabled, names, raw, path):
        # pylint: disable=too-many-arguments
        """Initialize a VH."""
        self.filep = filep
        self.addrs = addrs
        self.names = names
        self.ssl = ssl
        self.enabled = enabled
        self.raw = raw
        self.path = path

    def __str__(self):
        addr_str = ", ".join(str(addr) for addr in self.addrs)
        return ("file: %s\n"
                "addrs: %s\n"
                "names: %s\n"
                "ssl: %s\n"
                "enabled: %s" % (self.filep, addr_str,
                                 self.names, self.ssl, self.enabled))

    def __repr__(self):
        return "VirtualHost(" + self.__str__().replace("\n", ", ") + ")\n"

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return (self.filep == other.filep and
                    list(self.addrs) == list(other.addrs) and
                    self.names == other.names and
                    self.ssl == other.ssl and
                    self.enabled == other.enabled and
                    self.path == other.path)

        return False
