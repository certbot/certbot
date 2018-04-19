"""NginxParser is a member object of the NginxConfigurator class."""
import logging
import os
import re

import six

from certbot import errors

from certbot_nginx import nginxparser
from certbot_nginx import parser_obj

logger = logging.getLogger(__name__)

# TODO (sydli): Shouldn't be throwing Misconfiguration errors everywhere. Is there a parsing error?

INCLUDE = 'include'
REPEATABLE_DIRECTIVES = set(['server_name', 'listen', INCLUDE, 'rewrite'])
COMMENT = ' managed by Certbot'
COMMENT_BLOCK = ['#', COMMENT]

class FancyParser(object):
    """ Fancy nginx parser that tries to transform it into an AST of sorts.
    """
    def __init__(self, root_dir, config_root):
        self.parsed = {}
        self.parsed_root = None
        self.files = {}
        self.root = os.path.abspath(root_dir)
        self.config_root = self._find_config_root(config_root)

        # Parse nginx.conf and included files.
        # TODO: Check sites-available/ as well. For now, the configurator does
        # not enable sites from there.
        self.load()

    def _find_config_root(self, root_name):
        """Return the Nginx Configuration Root file."""
        location = [root_name]

        for name in location:
            if os.path.isfile(os.path.join(self.root, name)):
                return os.path.join(self.root, name)

        raise errors.NoInstallationError(
            "Could not find configuration root")

    def load(self):
        """Loads Nginx files into a parsed tree.
        """
        self.parsed_root = parser_obj.Statements.load_from(
                               parser_obj.ParseContext(self.root, self.config_root))
        self.parsed = {self.config_root: self.parsed_root}
        includes = self.parsed_root.get_thing_recursive(
                lambda sentence: isinstance(sentence, parser_obj.Sentence) and \
                                 sentence[0] == 'include')
        for include in includes:
            for filename, parsed in six.iteritems(include.parsed):
                self.parsed[os.path.join(self.root, filename)] = parsed

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

    def filedump(self, ext='tmp', lazy=True):
        """Dumps parsed configurations into files.

        :param str ext: The file extension to use for the dumped files. If
            empty, this overrides the existing conf files.
        :param bool lazy: Only write files that have been modified
         TODO (sydli): fix lazy flag

        """
        # pylint: disable=unused-argument
        # Best-effort atomicity is enforced above us by reverter.py
        for filename in self.parsed:
            tree = self.parsed[filename]
            if ext:
                filename = filename + os.path.extsep + ext
            try:
                # if lazy and not tree.is_dirty():
                #     continue
                out = nginxparser.dumps_raw(tree.get_data(include_spaces=True))
                logger.debug('Writing nginx conf tree to %s:\n%s', filename, out)
                with open(filename, 'w') as _file:
                    _file.write(out)

            except IOError:
                logger.error("Could not open file for writing: %s", filename)

    def get_vhosts(self):
        """Gets list of all 'virtual hosts' found in Nginx configuration.
        Technically this is a misnomer because Nginx does not have virtual
        hosts, it has 'server blocks'.

        :returns: List of :class:`~certbot_nginx.obj.VirtualHost`
            objects found in configuration
        :rtype: list

        """
        vhosts = []
        blocs = self.parsed_root.get_thing_recursive(lambda x: isinstance(x, parser_obj.ServerBloc))
        for server_bloc in blocs:
            vhosts.append(server_bloc.vhost)
        self._update_vhosts_addrs_global_ssl(vhosts)
        return vhosts

    def _build_global_addr_to_ssl(self):
        """Builds a map from address to whether it listens on ssl in any server block
        """
        addr_to_ssl = {}
        blocs = self.parsed_root.get_thing_recursive(lambda x: isinstance(x, parser_obj.ServerBloc))
        for server_bloc in blocs:
            for addr in server_bloc.addrs:
                addr_tuple = addr.normalized_tuple()
                if addr_tuple not in addr_to_ssl:
                    addr_to_ssl[addr_tuple] = addr.ssl
                addr_to_ssl[addr_tuple] = addr.ssl or addr_to_ssl[addr_tuple]
        return addr_to_ssl

    def _update_vhosts_addrs_global_ssl(self, vhosts):
        """Update a list of raw parsed vhosts to include global address sslishness
        """
        addr_to_ssl = self._build_global_addr_to_ssl()
        for vhost in vhosts:
            for addr in vhost.addrs:
                addr.ssl = addr_to_ssl[addr.normalized_tuple()]
                if addr.ssl:
                    vhost.ssl = True

    def has_ssl_on_directive(self, vhost):
        """Does vhost have ssl on for all ports?

        :param :class:`~certbot_nginx.obj.VirtualHost` vhost: The vhost in question

        :returns: True if 'ssl on' directive is included
        :rtype: bool

        """
        for ssl in vhost.raw.contents.get_directives("ssl"):
            if ssl[1] == "on":
                return True
        return False

    def add_server_directives(self, vhost, directives, insert_at_top=False, is_block=False):
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
        vhost.raw.add_directives(directives, insert_at_top, is_block)

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
        vhost.raw.replace_directives(directives, insert_at_top)

    def remove_server_directives(self, vhost, directive_name, match_func=None):
        """Remove all directives of type directive_name.

        :param :class:`~certbot_nginx.obj.VirtualHost` vhost: The vhost
            to remove directives from
        :param string directive_name: The directive type to remove
        :param callable match_func: Function of the directive that returns true for directives
            to be deleted.
        """
        vhost.raw.remove_directives(directive_name, match_func)

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
        dup_server_bloc = vhost_template.raw.duplicate(only_directives, remove_singleton_listen_params)
        return dup_server_bloc.vhost

class NginxParser(FancyParser):
    """Class handles the fine details of parsing the Nginx Configuration.

    :ivar str root: Normalized absolute path to the server root
        directory. Without trailing slash.
    :ivar dict parsed: Mapping of file paths to parsed trees

    """
    def __init__(self, root_dir, root_file="nginx.conf"):
        super(NginxParser, self).__init__(root_dir, root_file)

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

