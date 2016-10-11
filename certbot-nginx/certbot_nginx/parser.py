"""NginxParser is a member object of the NginxConfigurator class."""
import copy
import glob
import logging
import os
import pyparsing
import re

from certbot import errors

from certbot_nginx import obj
from certbot_nginx import nginxparser


logger = logging.getLogger(__name__)


class NginxParser(object):
    """Class handles the fine details of parsing the Nginx Configuration.

    :ivar str root: Normalized absolute path to the server root
        directory. Without trailing slash.
    :ivar dict parsed: Mapping of file paths to parsed trees

    """

    def __init__(self, root, ssl_options):
        self.parsed = {}
        self.root = os.path.abspath(root)
        self.loc = self._set_locations(ssl_options)

        # Parse nginx.conf and included files.
        # TODO: Check sites-available/ as well. For now, the configurator does
        # not enable sites from there.
        self.load()

    def load(self):
        """Loads Nginx files into a parsed tree.

        """
        self.parsed = {}
        self._parse_recursively(self.loc["root"])

    def _parse_recursively(self, filepath):
        """Parses nginx config files recursively by looking at 'include'
        directives inside 'http' and 'server' blocks. Note that this only
        reads Nginx files that potentially declare a virtual host.

        :param str filepath: The path to the files to parse, as a glob

        """
        filepath = self.abs_path(filepath)
        trees = self._parse_files(filepath)
        for tree in trees:
            for entry in tree:
                if _is_include_directive(entry):
                    # Parse the top-level included file
                    self._parse_recursively(entry[1])
                elif entry[0] == ['http'] or entry[0] == ['server']:
                    # Look for includes in the top-level 'http'/'server' context
                    for subentry in entry[1]:
                        if _is_include_directive(subentry):
                            self._parse_recursively(subentry[1])
                        elif entry[0] == ['http'] and subentry[0] == ['server']:
                            # Look for includes in a 'server' context within
                            # an 'http' context
                            for server_entry in subentry[1]:
                                if _is_include_directive(server_entry):
                                    self._parse_recursively(server_entry[1])

    def abs_path(self, path):
        """Converts a relative path to an absolute path relative to the root.
        Does nothing for paths that are already absolute.

        :param str path: The path
        :returns: The absolute path
        :rtype: str

        """
        if not os.path.isabs(path):
            return os.path.join(self.root, path)
        else:
            return path

    def get_vhosts(self):
        # pylint: disable=cell-var-from-loop
        """Gets list of all 'virtual hosts' found in Nginx configuration.
        Technically this is a misnomer because Nginx does not have virtual
        hosts, it has 'server blocks'.

        :returns: List of :class:`~certbot_nginx.obj.VirtualHost`
            objects found in configuration
        :rtype: list

        """
        enabled = True  # We only look at enabled vhosts for now
        vhosts = []
        servers = {}

        for filename in self.parsed:
            tree = self.parsed[filename]
            servers[filename] = []
            srv = servers[filename]  # workaround undefined loop var in lambdas

            # Find all the server blocks
            _do_for_subarray(tree, lambda x: x[0] == ['server'],
                             lambda x, y: srv.append((x[1], y)))

            # Find 'include' statements in server blocks and append their trees
            for i, (server, path) in enumerate(servers[filename]):
                new_server = self._get_included_directives(server)
                servers[filename][i] = (new_server, path)

        for filename in servers:
            for server, path in servers[filename]:
                # Parse the server block into a VirtualHost object

                parsed_server = parse_server(server)
                vhost = obj.VirtualHost(filename,
                                        parsed_server['addrs'],
                                        parsed_server['ssl'],
                                        enabled,
                                        parsed_server['names'],
                                        server,
                                        path)
                vhosts.append(vhost)

        return vhosts

    def _get_included_directives(self, block):
        """Returns array with the "include" directives expanded out by
        concatenating the contents of the included file to the block.

        :param list block:
        :rtype: list

        """
        result = copy.deepcopy(block)  # Copy the list to keep self.parsed idempotent
        for directive in block:
            if _is_include_directive(directive):
                included_files = glob.glob(
                    self.abs_path(directive[1]))
                for incl in included_files:
                    try:
                        result.extend(self.parsed[incl])
                    except KeyError:
                        pass
        return result

    def _parse_files(self, filepath, override=False):
        """Parse files from a glob

        :param str filepath: Nginx config file path
        :param bool override: Whether to parse a file that has been parsed
        :returns: list of parsed tree structures
        :rtype: list

        """
        files = glob.glob(filepath) # nginx on unix calls glob(3) for this
                                    # XXX Windows nginx uses FindFirstFile, and
                                    # should have a narrower call here
        trees = []
        for item in files:
            if item in self.parsed and not override:
                continue
            try:
                with open(item) as _file:
                    parsed = nginxparser.load(_file)
                    self.parsed[item] = parsed
                    trees.append(parsed)
            except IOError:
                logger.warning("Could not open file: %s", item)
            except pyparsing.ParseException:
                logger.debug("Could not parse file: %s", item)
        return trees

    def _parse_ssl_options(self, ssl_options):
        if ssl_options is not None:
            try:
                with open(ssl_options) as _file:
                    return nginxparser.load(_file).spaced
            except IOError:
                logger.warn("Missing NGINX TLS options file: %s", ssl_options)
            except pyparsing.ParseBaseException:
                logger.debug("Could not parse file: %s", ssl_options)
        return []

    def _set_locations(self, ssl_options):
        """Set default location for directives.

        Locations are given as file_paths
        .. todo:: Make sure that files are included

        """
        root = self._find_config_root()
        default = root

        nginx_temp = os.path.join(self.root, "nginx_ports.conf")
        if os.path.isfile(nginx_temp):
            listen = nginx_temp
            name = nginx_temp
        else:
            listen = default
            name = default

        return {"root": root, "default": default, "listen": listen,
                "name": name, "ssl_options": self._parse_ssl_options(ssl_options)}

    def _find_config_root(self):
        """Find the Nginx Configuration Root file."""
        location = ['nginx.conf']

        for name in location:
            if os.path.isfile(os.path.join(self.root, name)):
                return os.path.join(self.root, name)

        raise errors.NoInstallationError(
            "Could not find configuration root")

    def filedump(self, ext='tmp', lazy=True):
        """Dumps parsed configurations into files.

        :param str ext: The file extension to use for the dumped files. If
            empty, this overrides the existing conf files.
        :param bool lazy: Only write files that have been modified

        """
        # Best-effort atomicity is enforced above us by reverter.py
        for filename in self.parsed:
            tree = self.parsed[filename]
            if ext:
                filename = filename + os.path.extsep + ext
            try:
                if lazy and not tree.is_dirty():
                    continue
                out = nginxparser.dumps(tree)
                logger.debug('Writing nginx conf tree to %s:\n%s', filename, out)
                with open(filename, 'w') as _file:
                    _file.write(out)

            except IOError:
                logger.error("Could not open file for writing: %s", filename)

    def has_ssl_on_directive(self, vhost):
        """Does vhost have ssl on for all ports?

        :param :class:`~certbot_nginx.obj.VirtualHost` vhost: The vhost in question

        :returns: True if 'ssl on' directive is included
        :rtype: bool

        """
        server = vhost.raw
        for directive in server:
            if not directive or len(directive) < 2:
                continue
            elif directive[0] == 'ssl' and directive[1] == 'on':
                return True

        return False

    def add_server_directives(self, vhost, directives, replace):
        """Add or replace directives in the server block identified by vhost.

        This method modifies vhost to be fully consistent with the new directives.

        ..note :: If replace is True, this raises a misconfiguration error
        if the directive does not already exist.
        ..note :: If replace is False nothing gets added if an identical
        block exists already.

        ..todo :: Doesn't match server blocks whose server_name directives are
            split across multiple conf files.

        :param :class:`~certbot_nginx.obj.VirtualHost` vhost: The vhost
            whose information we use to match on
        :param list directives: The directives to add
        :param bool replace: Whether to only replace existing directives

        """
        filename = vhost.filep
        try:
            result = self.parsed[filename]
            for index in vhost.path:
                result = result[index]
            if not isinstance(result, list) or len(result) != 2:
                raise errors.MisconfigurationError("Not a server block.")
            result = result[1]
            _add_directives(result, directives, replace)

            # update vhost based on new directives
            new_server = self._get_included_directives(result)
            parsed_server = parse_server(new_server)
            vhost.addrs = parsed_server['addrs']
            vhost.ssl = parsed_server['ssl']
            vhost.names = parsed_server['names']
            vhost.raw = new_server
        except errors.MisconfigurationError as err:
            raise errors.MisconfigurationError("Problem in %s: %s" % (filename, err.message))

    def get_all_certs_keys(self):
        """Gets all certs and keys in the nginx config.

        :returns: list of tuples with form [(cert, key, path)]
            cert - str path to certificate file
            key - str path to associated key file
            path - File path to configuration file.
        :rtype: set

        """
        c_k = set()
        vhosts = self.get_vhosts()
        for vhost in vhosts:
            tup = [None, None, vhost.filep]
            if vhost.ssl:
                for directive in vhost.raw:
                    # A directive can be an empty list to preserve whitespace
                    if not directive:
                        continue
                    if directive[0] == 'ssl_certificate':
                        tup[0] = directive[1]
                    elif directive[0] == 'ssl_certificate_key':
                        tup[1] = directive[1]
            if tup[0] is not None and tup[1] is not None:
                c_k.add(tuple(tup))
        return c_k


def _do_for_subarray(entry, condition, func, path=None):
    """Executes a function for a subarray of a nested array if it matches
    the given condition.

    :param list entry: The list to iterate over
    :param function condition: Returns true iff func should be executed on item
    :param function func: The function to call for each matching item

    """
    if path is None:
        path = []
    if isinstance(entry, list):
        if condition(entry):
            func(entry, path)
        else:
            for index, item in enumerate(entry):
                _do_for_subarray(item, condition, func, path + [index])


def get_best_match(target_name, names):
    """Finds the best match for target_name out of names using the Nginx
    name-matching rules (exact > longest wildcard starting with * >
    longest wildcard ending with * > regex).

    :param str target_name: The name to match
    :param set names: The candidate server names
    :returns: Tuple of (type of match, the name that matched)
    :rtype: tuple

    """
    exact = []
    wildcard_start = []
    wildcard_end = []
    regex = []

    for name in names:
        if _exact_match(target_name, name):
            exact.append(name)
        elif _wildcard_match(target_name, name, True):
            wildcard_start.append(name)
        elif _wildcard_match(target_name, name, False):
            wildcard_end.append(name)
        elif _regex_match(target_name, name):
            regex.append(name)

    if len(exact) > 0:
        # There can be more than one exact match; e.g. eff.org, .eff.org
        match = min(exact, key=len)
        return ('exact', match)
    if len(wildcard_start) > 0:
        # Return the longest wildcard
        match = max(wildcard_start, key=len)
        return ('wildcard_start', match)
    if len(wildcard_end) > 0:
        # Return the longest wildcard
        match = max(wildcard_end, key=len)
        return ('wildcard_end', match)
    if len(regex) > 0:
        # Just return the first one for now
        match = regex[0]
        return ('regex', match)

    return (None, None)


def _exact_match(target_name, name):
    return target_name == name or '.' + target_name == name


def _wildcard_match(target_name, name, start):
    # Degenerate case
    if name == '*':
        return True

    parts = target_name.split('.')
    match_parts = name.split('.')

    # If the domain ends in a wildcard, do the match procedure in reverse
    if not start:
        parts.reverse()
        match_parts.reverse()

    # The first part must be a wildcard or blank, e.g. '.eff.org'
    first = match_parts.pop(0)
    if first != '*' and first != '':
        return False

    target_name = '.'.join(parts)
    name = '.'.join(match_parts)

    # Ex: www.eff.org matches *.eff.org, eff.org does not match *.eff.org
    return target_name.endswith('.' + name)


def _regex_match(target_name, name):
    # Must start with a tilde
    if len(name) < 2 or name[0] != '~':
        return False

    # After tilde is a perl-compatible regex
    try:
        regex = re.compile(name[1:])
        if re.match(regex, target_name):
            return True
        else:
            return False
    except re.error:  # pragma: no cover
        # perl-compatible regexes are sometimes not recognized by python
        return False


def _is_include_directive(entry):
    """Checks if an nginx parsed entry is an 'include' directive.

    :param list entry: the parsed entry
    :returns: Whether it's an 'include' directive
    :rtype: bool

    """
    return (isinstance(entry, list) and
            len(entry) == 2 and entry[0] == 'include' and
            isinstance(entry[1], str))


def _get_servernames(names):
    """Turns a server_name string into a list of server names

    :param str names: server names
    :rtype: list

    """
    whitespace_re = re.compile(r'\s+')
    names = re.sub(whitespace_re, ' ', names)
    return names.split(' ')


def parse_server(server):
    """Parses a list of server directives.

    :param list server: list of directives in a server block
    :rtype: dict

    """
    parsed_server = {'addrs': set(),
                     'ssl': False,
                     'names': set()}

    apply_ssl_to_all_addrs = False

    for directive in server:
        if not directive:
            continue
        if directive[0] == 'listen':
            addr = obj.Addr.fromstring(directive[1])
            parsed_server['addrs'].add(addr)
            if not parsed_server['ssl'] and addr.ssl:
                parsed_server['ssl'] = True
        elif directive[0] == 'server_name':
            parsed_server['names'].update(
                _get_servernames(directive[1]))
        elif directive[0] == 'ssl' and directive[1] == 'on':
            parsed_server['ssl'] = True
            apply_ssl_to_all_addrs = True

    if apply_ssl_to_all_addrs:
        for addr in parsed_server['addrs']:
            addr.ssl = True

    return parsed_server


def _add_directives(block, directives, replace):
    """Adds or replaces directives in a config block.

    When replace=False, it's an error to try and add a directive that already
    exists in the config block with a conflicting value.

    When replace=True, a directive with the same name MUST already exist in the
    config block, and the first instance will be replaced.

    ..todo :: Find directives that are in included files.

    :param list block: The block to replace in
    :param list directives: The new directives.

    """
    for directive in directives:
        _add_directive(block, directive, replace)
    if block and '\n' not in block[-1]:  # could be "   \n  " or ["\n"] !
        block.append(nginxparser.UnspacedList('\n'))


REPEATABLE_DIRECTIVES = set(['server_name', 'listen', 'include'])
COMMENT = ' managed by Certbot'
COMMENT_BLOCK = [' ', '#', COMMENT]


def _comment_directive(block, location):
    """Add a comment to the end of the line at location."""
    next_entry = block[location + 1] if location + 1 < len(block) else None
    if isinstance(next_entry, list) and next_entry:
        if len(next_entry) >= 2 and next_entry[-2] == "#" and COMMENT in next_entry[-1]:
            return
        elif isinstance(next_entry, nginxparser.UnspacedList):
            next_entry = next_entry.spaced[0]
        else:
            next_entry = next_entry[0]

    block.insert(location + 1, COMMENT_BLOCK[:])
    if next_entry is not None and "\n" not in next_entry:
        block.insert(location + 2, '\n')


def _add_directive(block, directive, replace):
    """Adds or replaces a single directive in a config block.

    See _add_directives for more documentation.

    """
    directive = nginxparser.UnspacedList(directive)
    if len(directive) == 0 or directive[0] == '#':
        # whitespace or comment
        block.append(directive)
        return

    # Find the index of a config line where the name of the directive matches
    # the name of the directive we want to add. If no line exists, use None.
    location = next((index for index, line in enumerate(block)
                     if line and line[0] == directive[0]), None)
    if replace:
        if location is None:
            raise errors.MisconfigurationError(
                'expected directive for {0} in the Nginx '
                'config but did not find it.'.format(directive[0]))
        block[location] = directive
        _comment_directive(block, location)
    else:
        # Append directive. Fail if the name is not a repeatable directive name,
        # and there is already a copy of that directive with a different value
        # in the config file.
        directive_name = directive[0]
        directive_value = directive[1]
        if location is None or (isinstance(directive_name, str) and
                                directive_name in REPEATABLE_DIRECTIVES):
            block.append(directive)
            _comment_directive(block, len(block) - 1)
        elif block[location][1] != directive_value:
            raise errors.MisconfigurationError(
                'tried to insert directive "{0}" but found '
                'conflicting "{1}".'.format(directive, block[location]))

