"""Module contains classes used by the Nginx Configurator."""
import re

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
        super().__init__((host, port))
        self.ssl = ssl
        self.default = default
        self.ipv6 = ipv6
        self.ipv6only = ipv6only
        self.unspecified_address = host in self.UNSPECIFIED_IPV4_ADDRESSES

    @classmethod
    def fromstring(cls, str_addr):
        """
        Initialize an Addr object from a string.

        :param str addr: The address to parse
        :returns: An Addr object if the string is valid, None otherwise
        """
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
        """
        :param filep: A string containing the file path.
        :param addrs: An iterable of :class:`~certbot_nginx._internal.obj.Addr` objects
            found in the
        file.
        :param names: An iterable of ssl server name values found in the file that are not IP addresses, i.e., they are domain names or ip-literal
        addresses with a zone identifier label (see RFC 6874). These server names are collected separately so that they can be easily processed after all
        other Addr objects have been removed from `addrs`. The elements of this list may be any type which may be cast to a string value (i.e., ``str`` or
        ``unicode``), but will ultimately be stored as strings when matching against a requested server name during SSL negotiation and/or OCSP stapling
        requests for this certificate unit's associated VirtualHosts). This allows for more flexible matching rules than would otherwise result from casting,
        e.g., an IPAddress object to its string representation only when matching against actual IP address request server names; it also allows for easier
        identification and processing of alternate SANs types such as email addresses compared to how such types would
        """
        """
        :param filep: A string containing the file path.
        :param addrs: An iterable of addresses that are associated with the directive.
        :param names: An
        iterable of names that are associated with the directive.
        :param ssl: A boolean indicating whether or not SSL is enabled for this server block (and
        therefore for all directives in it). Default False.
        """
        return self.to_string()

    def __repr__(self):
        return "Addr(" + self.__str__() + ")"

    def __hash__(self):  # pylint: disable=useless-super-delegation
        # Python 3 requires explicit overridden for __hash__
        # See certbot-apache/certbot_apache/_internal/obj.py for more information
        return super().__hash__()

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
        return super().__eq__(other)

    def __eq__(self, other):
        """
        :param filep: (optional) The full path to the file
        :param addrs: (optional) A list of addresses that are associated with this server block.
            :type
        addrs: :class:'~obj.Addr' or list of str

            If a str is passed, it will be converted to an :class:'~obj.Addr'

            .. note :: This paramater is
        optional even if the server block has non-TLS addresses, however it is necessary IF the server block has any TLS addresses and must be specified if
        there are any TLS addresses present in order for them to be included in the generated configuraton files.
                When no value is provided for this
        parameter, then all Addresses will not have a corresponding ``listen`` statement in their config section as required by most webservers including
        nginx when using SSL on only specific addresses..  However, if you do provide values here and some of those addressess are also found on other
        ServerBlocks which DO have an explicit ``listen`` staement defined already then those existing listen statements WILL NOT BE OVERWRITTEN!  In that
        case you should explicitly specify all desired listen directives via your call to `add_server_
        """
        """
        :param filep: (optional) The full path to the file
        :param addrs: (optional) A list of addresses that can be either IP or hostnames.
        These will be used in addition to any address found in ``filep``.
                      This is useful for adding extra addresses that are not present in the
        certificate, such as intermediate IPs.
                      Note that if you specify this and have an SNI name set, it will use this address as the CN name
        instead of sni_name.

          .. note :: If you want to pass a list of just ipv4/ipv6 addresses then use a :py:class`list` with elements like `['1.2.3',
        '5', '127']`.

          .. warning :: You must escape any IPv6 brackets using ``\\[\\]`` when passing a :py:class`list`. For example `['fe80\:\:/10']`.
        **Example** - Add extra ip's from our local DNS server into letsencrypt certficate generated by cloudflare which only has cloudflare's dns ip's listed
        on certficate and not our local ones we need for internal routing purposes.:
        """
        if isinstance(other, self.__class__):
            return (self.super_eq(other) and
                    self.ssl == other.ssl and
                    self.default == other.default)
        return False


class VirtualHost:
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
        """
        :param filep: A string containing the file path.
        :param addrs: An iterable of :class:`~certbot_nginx._internal.obj.Addr` objects
            found in the
        file.
        :param names: An iterable of ssl server name values found in the file that are not IP addresses, i.e., they are domain names or ip-literal
        addresses with a zone identifier label (see RFC 6874). These server names are collected separately so that they can be easily processed after all
        other Addr objects have been removed from `addrs`. The elements of this list may be any type which may be cast to a string value (i.e., ``str`` or
        ``unicode``), but will ultimately be stored as strings when matching against a requested server name during SSL negotiation and/or OCSP stapling
        requests for this certificate unit's associated VirtualHosts). This allows for more flexible matching rules than would otherwise result from casting,
        e.g., an IPAddress object to its string representation only when matching against actual IP address request server names; it also allows for easier
        identification and processing of alternate SANs types such as email addresses compared to how such types would
        """
        """
        :param filep: A string containing the file path.
        :param addrs: An iterable of addresses that are associated with the directive.
        :param names: An
        iterable of names that are associated with the directive.
        :param ssl: A boolean indicating whether or not SSL is enabled for this server block (and
        therefore for all directives in it). Default False.
        """
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
        """
        :param filep: (optional) The full path to the file
        :param addrs: (optional) A list of addresses that are associated with this server block.
            :type
        addrs: :class:'~obj.Addr' or list of str

            If a str is passed, it will be converted to an :class:'~obj.Addr'

            .. note :: This paramater is
        optional even if the server block has non-TLS addresses, however it is necessary IF the server block has any TLS addresses and must be specified if
        there are any TLS addresses present in order for them to be included in the generated configuraton files.
                When no value is provided for this
        parameter, then all Addresses will not have a corresponding ``listen`` statement in their config section as required by most webservers including
        nginx when using SSL on only specific addresses..  However, if you do provide values here and some of those addressess are also found on other
        ServerBlocks which DO have an explicit ``listen`` staement defined already then those existing listen statements WILL NOT BE OVERWRITTEN!  In that
        case you should explicitly specify all desired listen directives via your call to `add_server_
        """
        """
        :param filep: (optional) The full path to the file
        :param addrs: (optional) A list of addresses that can be either IP or hostnames.
        These will be used in addition to any address found in ``filep``.
                      This is useful for adding extra addresses that are not present in the
        certificate, such as intermediate IPs.
                      Note that if you specify this and have an SNI name set, it will use this address as the CN name
        instead of sni_name.

          .. note :: If you want to pass a list of just ipv4/ipv6 addresses then use a :py:class`list` with elements like `['1.2.3',
        '5', '127']`.

          .. warning :: You must escape any IPv6 brackets using ``\\[\\]`` when passing a :py:class`list`. For example `['fe80\:\:/10']`.
        **Example** - Add extra ip's from our local DNS server into letsencrypt certficate generated by cloudflare which only has cloudflare's dns ip's listed
        on certficate and not our local ones we need for internal routing purposes.:
        """
        if isinstance(other, self.__class__):
            return (self.filep == other.filep and
                    sorted(self.addrs, key=str) == sorted(other.addrs, key=str) and
                    self.names == other.names and
                    self.ssl == other.ssl and
                    self.enabled == other.enabled and
                    self.path == other.path)

        return False

    def __hash__(self):
        """
        :param filep:
            The full absolute path to the Apache configuration file.
        :param path:
            A list of directories that will be recursively searched
        for .conf files. This is usually left empty, and ``find_dir`` is used to locate configuration directories. Searching starts from the directory
        containing the original config file, and proceeds upwards through each parent directory until reaching "/". If you wish to limit the search path, you
        may pass a list of directories that will be searched in order starting from the Apache root directory (ie ``/etc/httpd``). All relative paths are
        relative to Apache's root directory ``/etc`` unless they start with "../" or "./". For example, if this parameter was set to ["/srv", "/home"], then
        find_dir would first look in "/srv" and then in "/home", before returning an error message indicating that no such directive could be found. Note that
        this parameter can only contain *directories*; it cannot contain regular expressions or wildcards like "*.conf".
        :param addrs:
            A tuple of server
        addresses passed into :class`~certbot_apache._internal.obj.Addr`. Both string objects and tu
        """
        """
        :param filep: The absolute path to the Apache configuration file.
        :type filep: str

        :param path: A list of directories that will be searched to find
        the full path of ``filep`` when ``__init__`` is called.
        :type path: list

        :param addrs: A tuple of ``(ip, port)`` pairs where each pair represents one
        or more addresses that this vhost listens on.
                        * If the address is an IP address, then it should be a string in the form "12.34.56.78".
        Alternatively, if it's an IPv6 address then you should use square brackets around it (e.g., "[fe80:[aef0...]]").
                        * If a socket family
        is specified as "*", then this refers to both TCP and Unix domain sockets for backwards compatibility reasons (i think). This was originally
        introduced for Mac OS X where there are two types of sockets - one for IPv4 and another for IPv6 which are incompatible with each other ("can't mix
        apples and oranges"). Since we're only concerned with parsing files here rather than actually running servers on ports or anything like that, I don't
        think we need to worry
        """
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
        for i in range(0, len(self.raw) - len(test) + 1):
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
    if not directives or isinstance(directives, str):
        return None

    # If match_content is None, just match on directive type. Otherwise, match on
    # both directive type -and- the content!
    if directives[0] == directive_name and \
            (match_content is None or match_content in directives):
        return directives

    matches = (_find_directive(line, directive_name, match_content) for line in directives)
    return next((m for m in matches if m is not None), None)
