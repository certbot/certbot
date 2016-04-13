"""NginxParser is a member object of the NginxConfigurator class."""
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

    :ivar str root: Normalized abosulte path to the server root
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
                             lambda x: srv.append(x[1]))

            # Find 'include' statements in server blocks and append their trees
            for i, server in enumerate(servers[filename]):
                new_server = self._get_included_directives(server)
                servers[filename][i] = new_server

        for filename in servers:
            for server in servers[filename]:
                # Parse the server block into a VirtualHost object
                parsed_server = parse_server(server)
                vhost = obj.VirtualHost(filename,
                                        parsed_server['addrs'],
                                        parsed_server['ssl'],
                                        enabled,
                                        parsed_server['names'],
                                        server)
                vhosts.append(vhost)

        return vhosts

    def _get_included_directives(self, block):
        """Returns array with the "include" directives expanded out by
        concatenating the contents of the included file to the block.

        :param list block:
        :rtype: list

        """
        result = list(block)  # Copy the list to keep self.parsed idempotent
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
        files = glob.glob(filepath)
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
                logger.warn("Could not open file: %s", item)
            except pyparsing.ParseException:
                logger.debug("Could not parse file: %s", item)
        return trees

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
                "name": name, "ssl_options": ssl_options}

    def _find_config_root(self):
        """Find the Nginx Configuration Root file."""
        location = ['nginx.conf']

        for name in location:
            if os.path.isfile(os.path.join(self.root, name)):
                return os.path.join(self.root, name)

        raise errors.NoInstallationError(
            "Could not find configuration root")

    def filedump(self, ext='tmp'):
        """Dumps parsed configurations into files.

        :param str ext: The file extension to use for the dumped files. If
            empty, this overrides the existing conf files.

        """
        for filename in self.parsed:
            tree = self.parsed[filename]
            if ext:
                filename = filename + os.path.extsep + ext
            try:
                logger.debug('Dumping to %s:\n%s', filename, nginxparser.dumps(tree))
                with open(filename, 'w') as _file:
                    nginxparser.dump(tree, _file)
            except IOError:
                logger.error("Could not open file for writing: %s", filename)

    def _has_server_names(self, entry, names):
        """Checks if a server block has the given set of server_names. This
        is the primary way of identifying server blocks in the configurator.
        Returns false if 'entry' doesn't look like a server block at all.

        ..todo :: Doesn't match server blocks whose server_name directives are
        split across multiple conf files.

        :param list entry: The block to search
        :param set names: The names to match
        :rtype: bool

        """
        if len(names) == 0:
            # Nothing to identify blocks with
            return False

        if not isinstance(entry, list):
            # Can't be a server block
            return False

        new_entry = self._get_included_directives(entry)
        server_names = set()
        for item in new_entry:
            if not isinstance(item, list):
                # Can't be a server block
                return False

            if len(item) > 0 and item[0] == 'server_name':
                server_names.update(_get_servernames(item[1]))

        return server_names == names

    def add_server_directives(self, filename, names, directives,
                              replace):
        """Add or replace directives in the first server block with names.

        ..note :: If replace is True, this raises a misconfiguration error
        if the directive does not already exist.
        ..note :: If replace is False nothing gets added if an identical
        block exists already.

        ..todo :: Doesn't match server blocks whose server_name directives are
            split across multiple conf files.

        :param str filename: The absolute filename of the config file
        :param set names: The server_name to match
        :param list directives: The directives to add
        :param bool replace: Whether to only replace existing directives

        """
        try:
            _do_for_subarray(self.parsed[filename],
                             lambda x: self._has_server_names(x, names),
                             lambda x: _add_directives(x, directives, replace))
        except errors.MisconfigurationError as err:
            raise errors.MisconfigurationError("Problem in %s: %s" % (filename, err.message))

    def add_http_directives(self, filename, directives):
        """Adds directives to the first encountered HTTP block in filename.

        We insert new directives at the top of the block to work around
        https://trac.nginx.org/nginx/ticket/810: If the first server block
        doesn't enable OCSP stapling, stapling is broken for all blocks.

        :param str filename: The absolute filename of the config file
        :param list directives: The directives to add

        """
        _do_for_subarray(self.parsed[filename],
                         lambda x: x[0] == ['http'],
                         lambda x: x[1].insert(0, directives))

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
                    if directive[0] == 'ssl_certificate':
                        tup[0] = directive[1]
                    elif directive[0] == 'ssl_certificate_key':
                        tup[1] = directive[1]
            if tup[0] is not None and tup[1] is not None:
                c_k.add(tuple(tup))
        return c_k


def _do_for_subarray(entry, condition, func):
    """Executes a function for a subarray of a nested array if it matches
    the given condition.

    :param list entry: The list to iterate over
    :param function condition: Returns true iff func should be executed on item
    :param function func: The function to call for each matching item

    """
    if isinstance(entry, list):
        if condition(entry):
            func(entry)
        else:
            for item in entry:
                _do_for_subarray(item, condition, func)


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

    for directive in server:
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

repeatable_directives = set(['server_name', 'listen', 'include'])

def _add_directive(block, directive, replace):
    """Adds or replaces a single directive in a config block.

    See _add_directives for more documentation.

    """
    location = -1
    # Find the index of a config line where the name of the directive matches
    # the name of the directive we want to add.
    for index, line in enumerate(block):
        if len(line) > 0 and line[0] == directive[0]:
            location = index
            break
    if replace:
        if location == -1:
            raise errors.MisconfigurationError(
                'expected directive for %s in the Nginx '
                'config but did not find it.' % directive[0])
        block[location] = directive
    else:
        # Append directive. Fail if the name is not a repeatable directive name,
        # and there is already a copy of that directive with a different value
        # in the config file.
        directive_name = directive[0]
        directive_value = directive[1]
        if location != -1 and directive_name.__str__() not in repeatable_directives:
            if block[location][1] == directive_value:
                # There's a conflict, but the existing value matches the one we
                # want to insert, so it's fine.
                pass
            else:
                raise errors.MisconfigurationError(
                    'tried to insert directive "%s" but found conflicting "%s".' % (
                    directive, block[location]))
        else:
            block.append(directive)
