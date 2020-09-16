"""Module contains classes used by the Nginx Configurator."""
import re

import six

from certbot.plugins import common

ADD_HEADER_DIRECTIVE = 'add_header'

class Addr(common.Addr):
    r"""Represents an Nginx address, i.e. what comes after the 'listen'
    directive.

    According to the `documentation`_, this may be address[:port], port,
    or unix:path. The latter is ignored here.

    The default value if no directive is specified is \*:80 (superuser)
    or \*:8000 (otherwise). If no port is specified, the default is
    80. If no address is specified, listen on all addresses.

    .. _documentation:
       https://nginx.org/en/docs/http/ngx_http_core_module.html#listen

    .. todo:: Old-style nginx configs define SSL vhosts in a separate
              block instead of using 'ssl' in the listen directive.

    :param str addr: addr part of vhost address, may be hostname, IPv4, IPv6,
        "", or "\*"
    :param str port: port number or "\*" or ""
    :param bool ssl: Whether the directive includes 'ssl'
    :param bool default: Whether the directive includes 'default_server'
    :param bool default: Whether this is an IPv6 address
    :param bool ipv6only: Whether the directive includes 'ipv6only=on'

    """
    UNSPECIFIED_IPV4_ADDRESSES = ('', '*', '0.0.0.0')
    CANONICAL_UNSPECIFIED_ADDRESS = UNSPECIFIED_IPV4_ADDRESSES[0]

    def __init__(self, host, port, ssl, default, ipv6, ipv6only):
        super(Addr, self).__init__((host, port))
        self.ssl = ssl
        self.default = default
        self.ipv6 = ipv6
        self.ipv6only = ipv6only
        self.unspecified_address = host in self.UNSPECIFIED_IPV4_ADDRESSES

    @classmethod
    def fromstring(cls, str_addr):
        """Initialize Addr from string."""
        parts = str_addr.split(' ')
        ssl = False
        default = False
        ipv6 = False
        ipv6only = False
        host = ''
        port = ''

        # The first part must be the address
        addr = parts.pop(0)

        # Ignore UNIX-domain sockets
        if addr.startswith('unix:'):
            return None

        # IPv6 check
        ipv6_match = re.match(r'\[.*\]', addr)
        if ipv6_match:
            ipv6 = True
            # IPv6 handling
            host = ipv6_match.group()
            # The rest of the addr string will be the port, if any
            port = addr[ipv6_match.end()+1:]
        else:
            # IPv4 handling
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
        while parts:
            nextpart = parts.pop()
            if nextpart == 'ssl':
                ssl = True
            elif nextpart == 'default_server':
                default = True
            elif nextpart == 'default':
                default = True
            elif nextpart == "ipv6only=on":
                ipv6only = True

        return cls(host, port, ssl, default, ipv6, ipv6only)

    def to_string(self, include_default=True):
        """Return string representation of Addr"""
        parts = ''
        if self.tup[0] and self.tup[1]:
            parts = "%s:%s" % self.tup
        elif self.tup[0]:
            parts = self.tup[0]
        else:
            parts = self.tup[1]

        if self.default and include_default:
            parts += ' default_server'
        if self.ssl:
            parts += ' ssl'

        return parts

    def __str__(self):
        return self.to_string()

    def __repr__(self):
        return "Addr(" + self.__str__() + ")"

    def __hash__(self):  # pylint: disable=useless-super-delegation
        # Python 3 requires explicit overridden for __hash__
        # See certbot-apache/certbot_apache/_internal/obj.py for more information
        return super(Addr, self).__hash__()

    def super_eq(self, other):
        """Check ip/port equality, with IPv6 support.
        """
        # If both addresses got an unspecified address, then make sure the
        # host representation in each match when doing the comparison.
        if self.unspecified_address and other.unspecified_address:
            return common.Addr((self.CANONICAL_UNSPECIFIED_ADDRESS,
                                self.tup[1]), self.ipv6) == \
                   common.Addr((other.CANONICAL_UNSPECIFIED_ADDRESS,
                                other.tup[1]), other.ipv6)
        return super(Addr, self).__eq__(other)

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return (self.super_eq(other) and
                    self.ssl == other.ssl and
                    self.default == other.default)
        return False


class VirtualHost(object):
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
        """Initialize a VH."""
        self.filep = filep
        self.addrs = addrs
        self.names = names
        self.ssl = ssl
        self.enabled = enabled
        self.raw = raw
        self.path = path

    def __str__(self):
        addr_str = ", ".join(str(addr) for addr in sorted(self.addrs, key=str))
        # names might be a set, and it has different representations in Python
        # 2 and 3. Force it to be a list here for consistent outputs
        return ("file: %s\n"
                "addrs: %s\n"
                "names: %s\n"
                "ssl: %s\n"
                "enabled: %s" % (self.filep, addr_str,
                                 list(self.names), self.ssl, self.enabled))

    def __repr__(self):
        return "VirtualHost(" + self.__str__().replace("\n", ", ") + ")\n"

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return (self.filep == other.filep and
                    sorted(self.addrs, key=str) == sorted(other.addrs, key=str) and
                    self.names == other.names and
                    self.ssl == other.ssl and
                    self.enabled == other.enabled and
                    self.path == other.path)

        return False

    def __hash__(self):
        return hash((self.filep, tuple(self.path),
                     tuple(self.addrs), tuple(self.names),
                     self.ssl, self.enabled))

    def has_header(self, header_name):
        """Determine if this server block has a particular header set.
        :param str header_name: The name of the header to check for, e.g.
            'Strict-Transport-Security'
        """
        found = _find_directive(self.raw, ADD_HEADER_DIRECTIVE, header_name)
        return found is not None

    def contains_list(self, test):
        """Determine if raw server block contains test list at top level
        """
        for i in six.moves.range(0, len(self.raw) - len(test) + 1):
            if self.raw[i:i + len(test)] == test:
                return True
        return False

    def ipv6_enabled(self):
        """Return true if one or more of the listen directives in vhost supports
        IPv6"""
        for a in self.addrs:
            if a.ipv6:
                return True
        return False

    def ipv4_enabled(self):
        """Return true if one or more of the listen directives in vhost are IPv4
        only"""
        if not self.addrs:
            return True
        for a in self.addrs:
            if not a.ipv6:
                return True
        return False

    def display_repr(self):
        """Return a representation of VHost to be used in dialog"""
        return (
            "File: {filename}\n"
            "Addresses: {addrs}\n"
            "Names: {names}\n"
            "HTTPS: {https}\n".format(
                filename=self.filep,
                addrs=", ".join(str(addr) for addr in self.addrs),
                names=", ".join(self.names),
                https="Yes" if self.ssl else "No"))

def _find_directive(directives, directive_name, match_content=None):
    """Find a directive of type directive_name in directives. If match_content is given,
       Searches for `match_content` in the directive arguments.
    """
    if not directives or isinstance(directives, six.string_types):
        return None

    # If match_content is None, just match on directive type. Otherwise, match on
    # both directive type -and- the content!
    if directives[0] == directive_name and \
            (match_content is None or match_content in directives):
        return directives

    matches = (_find_directive(line, directive_name, match_content) for line in directives)
    return next((m for m in matches if m is not None), None)
