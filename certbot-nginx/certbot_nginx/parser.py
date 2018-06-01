"""NginxParser is a member object of the NginxConfigurator class."""
import copy
import functools
import glob
import logging
import os
import pyparsing
import re

import six

from certbot import errors

from certbot_nginx import obj
from certbot_nginx import nginxparser
from acme.magic_typing import Union, Dict, Set, Any, List, Tuple # pylint: disable=unused-import, no-name-in-module

logger = logging.getLogger(__name__)


class NginxParser(object):
    """Class handles the fine details of parsing the Nginx Configuration.

    :ivar str root: Normalized absolute path to the server root
        directory. Without trailing slash.
    :ivar dict parsed: Mapping of file paths to parsed trees

    """

    def __init__(self, root):
        self.parsed = {} # type: Dict[str, Union[List, nginxparser.UnspacedList]]
        self.root = os.path.abspath(root)
        self.config_root = self._find_config_root()

        # Parse nginx.conf and included files.
        # TODO: Check sites-available/ as well. For now, the configurator does
        # not enable sites from there.
        self.load()

    def load(self):
        """Loads Nginx files into a parsed tree.

        """
        self.parsed = {}
        self._parse_recursively(self.config_root)

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

    def _build_addr_to_ssl(self):
        """Builds a map from address to whether it listens on ssl in any server block
        """
        servers = self._get_raw_servers()

        addr_to_ssl = {} # type: Dict[Tuple[str, str], bool]
        for filename in servers:
            for server, _ in servers[filename]:
                # Parse the server block to save addr info
                parsed_server = _parse_server_raw(server)
                for addr in parsed_server['addrs']:
                    addr_tuple = addr.normalized_tuple()
                    if addr_tuple not in addr_to_ssl:
                        addr_to_ssl[addr_tuple] = addr.ssl
                    addr_to_ssl[addr_tuple] = addr.ssl or addr_to_ssl[addr_tuple]
        return addr_to_ssl

    def _get_raw_servers(self):
        # pylint: disable=cell-var-from-loop
        # type: () -> Dict
        """Get a map of unparsed all server blocks
        """
        servers = {} # type: Dict[str, Union[List, nginxparser.UnspacedList]]
        for filename in self.parsed:
            tree = self.parsed[filename]
            servers[filename] = []
            srv = servers[filename]  # workaround undefined loop var in lambdas

            # Find all the server blocks
            _do_for_subarray(tree, lambda x: len(x) >= 2 and x[0] == ['server'],
                             lambda x, y: srv.append((x[1], y)))

            # Find 'include' statements in server blocks and append their trees
            for i, (server, path) in enumerate(servers[filename]):
                new_server = self._get_included_directives(server)
                servers[filename][i] = (new_server, path)
        return servers

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
        servers = self._get_raw_servers()

        vhosts = []
        for filename in servers:
            for server, path in servers[filename]:
                # Parse the server block into a VirtualHost object

                parsed_server = _parse_server_raw(server)
                vhost = obj.VirtualHost(filename,
                                        parsed_server['addrs'],
                                        parsed_server['ssl'],
                                        enabled,
                                        parsed_server['names'],
                                        server,
                                        path)
                vhosts.append(vhost)

        self._update_vhosts_addrs_ssl(vhosts)

        return vhosts

    def _update_vhosts_addrs_ssl(self, vhosts):
        """Update a list of raw parsed vhosts to include global address sslishness
        """
        addr_to_ssl = self._build_addr_to_ssl()
        for vhost in vhosts:
            for addr in vhost.addrs:
                addr.ssl = addr_to_ssl[addr.normalized_tuple()]
                if addr.ssl:
                    vhost.ssl = True

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
            except pyparsing.ParseException as err:
                logger.debug("Could not parse file: %s due to %s", item, err)
        return trees

    def _find_config_root(self):
        """Return the Nginx Configuration Root file."""
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

    def parse_server(self, server):
        """Parses a list of server directives, accounting for global address sslishness.

        :param list server: list of directives in a server block
        :rtype: dict
        """
        addr_to_ssl = self._build_addr_to_ssl()
        parsed_server = _parse_server_raw(server)
        _apply_global_addr_ssl(addr_to_ssl, parsed_server)
        return parsed_server

    def has_ssl_on_directive(self, vhost):
        """Does vhost have ssl on for all ports?

        :param :class:`~certbot_nginx.obj.VirtualHost` vhost: The vhost in question

        :returns: True if 'ssl on' directive is included
        :rtype: bool

        """
        server = vhost.raw
        for directive in server:
            if not directive:
                continue
            elif _is_ssl_on_directive(directive):
                return True

        return False

    def add_server_directives(self, vhost, directives, insert_at_top=False):
        """Add directives to the server block identified by vhost.

        This method modifies vhost to be fully consistent with the new directives.

        ..note :: It's an error to try and add a nonrepeatable directive that already
            exists in the config block with a conflicting value.

        ..todo :: Doesn't match server blocks whose server_name directives are
            split across multiple conf files.

        :param :class:`~certbot_nginx.obj.VirtualHost` vhost: The vhost
            whose information we use to match on
        :param list directives: The directives to add
        :param bool insert_at_top: True if the directives need to be inserted at the top
            of the server block instead of the bottom

        """
        self._modify_server_directives(vhost,
            functools.partial(_add_directives, directives, insert_at_top))

    def update_or_add_server_directives(self, vhost, directives, insert_at_top=False):
        """Add or replace directives in the server block identified by vhost.

        This method modifies vhost to be fully consistent with the new directives.

        ..note :: When a directive with the same name already exists in the
        config block, the first instance will be replaced. Otherwise, the directive
        will be appended/prepended to the config block as in add_server_directives.

        ..todo :: Doesn't match server blocks whose server_name directives are
            split across multiple conf files.

        :param :class:`~certbot_nginx.obj.VirtualHost` vhost: The vhost
            whose information we use to match on
        :param list directives: The directives to add
        :param bool insert_at_top: True if the directives need to be inserted at the top
            of the server block instead of the bottom

        """
        self._modify_server_directives(vhost,
            functools.partial(_update_or_add_directives, directives, insert_at_top))

    def remove_server_directives(self, vhost, directive_name, match_func=None):
        """Remove all directives of type directive_name.

        :param :class:`~certbot_nginx.obj.VirtualHost` vhost: The vhost
            to remove directives from
        :param string directive_name: The directive type to remove
        :param callable match_func: Function of the directive that returns true for directives
            to be deleted.
        """
        self._modify_server_directives(vhost,
            functools.partial(_remove_directives, directive_name, match_func))

    def _update_vhost_based_on_new_directives(self, vhost, directives_list):
        new_server = self._get_included_directives(directives_list)
        parsed_server = self.parse_server(new_server)
        vhost.addrs = parsed_server['addrs']
        vhost.ssl = parsed_server['ssl']
        vhost.names = parsed_server['names']
        vhost.raw = new_server

    def _modify_server_directives(self, vhost, block_func):
        filename = vhost.filep
        try:
            result = self.parsed[filename]
            for index in vhost.path:
                result = result[index]
            if not isinstance(result, list) or len(result) != 2:
                raise errors.MisconfigurationError("Not a server block.")
            result = result[1]
            block_func(result)

            self._update_vhost_based_on_new_directives(vhost, result)
        except errors.MisconfigurationError as err:
            raise errors.MisconfigurationError("Problem in %s: %s" % (filename, str(err)))

    def duplicate_vhost(self, vhost_template, remove_singleton_listen_params=False,
        only_directives=None):
        """Duplicate the vhost in the configuration files.

        :param :class:`~certbot_nginx.obj.VirtualHost` vhost_template: The vhost
            whose information we copy
        :param bool remove_singleton_listen_params: If we should remove parameters
            from listen directives in the block that can only be used once per address
        :param list only_directives: If it exists, only duplicate the named directives. Only
            looks at first level of depth; does not expand includes.

        :returns: A vhost object for the newly created vhost
        :rtype: :class:`~certbot_nginx.obj.VirtualHost`
        """
        # TODO: https://github.com/certbot/certbot/issues/5185
        # put it in the same file as the template, at the same level
        new_vhost = copy.deepcopy(vhost_template)

        enclosing_block = self.parsed[vhost_template.filep]
        for index in vhost_template.path[:-1]:
            enclosing_block = enclosing_block[index]
        raw_in_parsed = copy.deepcopy(enclosing_block[vhost_template.path[-1]])

        if only_directives is not None:
            new_directives = nginxparser.UnspacedList([])
            for directive in raw_in_parsed[1]:
                if len(directive) > 0 and directive[0] in only_directives:
                    new_directives.append(directive)
            raw_in_parsed[1] = new_directives

            self._update_vhost_based_on_new_directives(new_vhost, new_directives)

        enclosing_block.append(raw_in_parsed)
        new_vhost.path[-1] = len(enclosing_block) - 1
        if remove_singleton_listen_params:
            for addr in new_vhost.addrs:
                addr.default = False
                addr.ipv6only = False
            for directive in enclosing_block[new_vhost.path[-1]][1]:
                if len(directive) > 0 and directive[0] == 'listen':
                    if 'default_server' in directive:
                        del directive[directive.index('default_server')]
                    if 'default' in directive:
                        del directive[directive.index('default')]
                    if 'ipv6only=on' in directive:
                        del directive[directive.index('ipv6only=on')]
        return new_vhost


def _parse_ssl_options(ssl_options):
    if ssl_options is not None:
        try:
            with open(ssl_options) as _file:
                return nginxparser.load(_file)
        except IOError:
            logger.warn("Missing NGINX TLS options file: %s", ssl_options)
        except pyparsing.ParseBaseException as err:
            logger.debug("Could not parse file: %s due to %s", ssl_options, err)
    return []

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
            isinstance(entry[1], six.string_types))

def _is_ssl_on_directive(entry):
    """Checks if an nginx parsed entry is an 'ssl on' directive.

    :param list entry: the parsed entry
    :returns: Whether it's an 'ssl on' directive
    :rtype: bool

    """
    return (isinstance(entry, list) and
            len(entry) == 2 and entry[0] == 'ssl' and
            entry[1] == 'on')

def _add_directives(directives, insert_at_top, block):
    """Adds directives to a config block."""
    for directive in directives:
        _add_directive(block, directive, insert_at_top)
    if block and '\n' not in block[-1]:  # could be "   \n  " or ["\n"] !
        block.append(nginxparser.UnspacedList('\n'))

def _update_or_add_directives(directives, insert_at_top, block):
    """Adds or replaces directives in a config block."""
    for directive in directives:
        _update_or_add_directive(block, directive, insert_at_top)
    if block and '\n' not in block[-1]:  # could be "   \n  " or ["\n"] !
        block.append(nginxparser.UnspacedList('\n'))


INCLUDE = 'include'
REPEATABLE_DIRECTIVES = set(['server_name', 'listen', INCLUDE, 'rewrite'])
COMMENT = ' managed by Certbot'
COMMENT_BLOCK = [' ', '#', COMMENT]

def comment_directive(block, location):
    """Add a ``#managed by Certbot`` comment to the end of the line at location.

    :param list block: The block containing the directive to be commented
    :param int location: The location within ``block`` of the directive to be commented
    """
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

def _comment_out_directive(block, location, include_location):
    """Comment out the line at location, with a note of explanation."""
    comment_message = ' duplicated in {0}'.format(include_location)
    # add the end comment
    # create a dumpable object out of block[location] (so it includes the ;)
    directive = block[location]
    new_dir_block = nginxparser.UnspacedList([]) # just a wrapper
    new_dir_block.append(directive)
    dumped = nginxparser.dumps(new_dir_block)
    commented = dumped + ' #' + comment_message # add the comment directly to the one-line string
    new_dir = nginxparser.loads(commented) # reload into UnspacedList

    # add the beginning comment
    insert_location = 0
    if new_dir[0].spaced[0] != new_dir[0][0]: # if there's whitespace at the beginning
        insert_location = 1
    new_dir[0].spaced.insert(insert_location, "# ") # comment out the line
    new_dir[0].spaced.append(";") # directly add in the ;, because now dumping won't work properly
    dumped = nginxparser.dumps(new_dir)
    new_dir = nginxparser.loads(dumped) # reload into an UnspacedList

    block[location] = new_dir[0] # set the now-single-line-comment directive back in place

def _find_location(block, directive_name, match_func=None):
    """Finds the index of the first instance of directive_name in block.
       If no line exists, use None."""
    return next((index for index, line in enumerate(block) \
        if line and line[0] == directive_name and (match_func is None or match_func(line))), None)

def _is_whitespace_or_comment(directive):
    """Is this directive either a whitespace or comment directive?"""
    return len(directive) == 0 or directive[0] == '#'

def _add_directive(block, directive, insert_at_top):
    if not isinstance(directive, nginxparser.UnspacedList):
        directive = nginxparser.UnspacedList(directive)
    if _is_whitespace_or_comment(directive):
        # whitespace or comment
        block.append(directive)
        return

    location = _find_location(block, directive[0])

    # Append or prepend directive. Fail if the name is not a repeatable directive name,
    # and there is already a copy of that directive with a different value
    # in the config file.

    # handle flat include files

    directive_name = directive[0]
    def can_append(loc, dir_name):
        """ Can we append this directive to the block? """
        return loc is None or (isinstance(dir_name, six.string_types)
            and dir_name in REPEATABLE_DIRECTIVES)

    err_fmt = 'tried to insert directive "{0}" but found conflicting "{1}".'

    # Give a better error message about the specific directive than Nginx's "fail to restart"
    if directive_name == INCLUDE:
        # in theory, we might want to do this recursively, but in practice, that's really not
        # necessary because we know what file we're talking about (and if we don't recurse, we
        # just give a worse error message)
        included_directives = _parse_ssl_options(directive[1])

        for included_directive in included_directives:
            included_dir_loc = _find_location(block, included_directive[0])
            included_dir_name = included_directive[0]
            if not _is_whitespace_or_comment(included_directive) \
                and not can_append(included_dir_loc, included_dir_name):
                if block[included_dir_loc] != included_directive:
                    raise errors.MisconfigurationError(err_fmt.format(included_directive,
                        block[included_dir_loc]))
                else:
                    _comment_out_directive(block, included_dir_loc, directive[1])

    if can_append(location, directive_name):
        if insert_at_top:
            # Add a newline so the comment doesn't comment
            # out existing directives
            block.insert(0, nginxparser.UnspacedList('\n'))
            block.insert(0, directive)
            comment_directive(block, 0)
        else:
            block.append(directive)
            comment_directive(block, len(block) - 1)
    elif block[location] != directive:
        raise errors.MisconfigurationError(err_fmt.format(directive, block[location]))

def _update_directive(block, directive, location):
    block[location] = directive
    comment_directive(block, location)

def _update_or_add_directive(block, directive, insert_at_top):
    if not isinstance(directive, nginxparser.UnspacedList):
        directive = nginxparser.UnspacedList(directive)
    if _is_whitespace_or_comment(directive):
        # whitespace or comment
        block.append(directive)
        return

    location = _find_location(block, directive[0])

    # we can update directive
    if location is not None:
        _update_directive(block, directive, location)
        return

    _add_directive(block, directive, insert_at_top)

def _is_certbot_comment(directive):
    return '#' in directive and COMMENT in directive

def _remove_directives(directive_name, match_func, block):
    """Removes directives of name directive_name from a config block if match_func matches.
    """
    while True:
        location = _find_location(block, directive_name, match_func=match_func)
        if location is None:
            return
        # if the directive was made by us, remove the comment following
        if location + 1 < len(block) and _is_certbot_comment(block[location + 1]):
            del block[location + 1]
        del block[location]

def _apply_global_addr_ssl(addr_to_ssl, parsed_server):
    """Apply global sslishness information to the parsed server block
    """
    for addr in parsed_server['addrs']:
        addr.ssl = addr_to_ssl[addr.normalized_tuple()]
        if addr.ssl:
            parsed_server['ssl'] = True

def _parse_server_raw(server):
    """Parses a list of server directives.

    :param list server: list of directives in a server block
    :rtype: dict

    """
    addrs = set() # type: Set[obj.Addr]
    ssl = False # type: bool
    names = set() # type: Set[str]

    apply_ssl_to_all_addrs = False

    for directive in server:
        if not directive:
            continue
        if directive[0] == 'listen':
            addr = obj.Addr.fromstring(" ".join(directive[1:]))
            if addr:
                addrs.add(addr)
                if addr.ssl:
                    ssl = True
        elif directive[0] == 'server_name':
            names.update(x.strip('"\'') for x in directive[1:])
        elif _is_ssl_on_directive(directive):
            ssl = True
            apply_ssl_to_all_addrs = True

    if apply_ssl_to_all_addrs:
        for addr in addrs:
            addr.ssl = True

    return {
        'addrs': addrs,
        'ssl': ssl,
        'names': names
    }
