"""NginxParser is a member object of the NginxConfigurator class."""
import abc
import copy
import itertools
import functools
import glob
import logging
import os
import pyparsing
import re

import six

from certbot import errors

from certbot_nginx import nginxparser
from certbot_nginx import parser
from certbot_nginx import obj

logger = logging.getLogger(__name__)

# TODO (sydli): Shouldn't be throwing Misconfiguration errors everywhere. Is there a parsing error?

class ParseContext:
    def __init__(self, cwd, filename, parent=None):
        self.cwd = cwd
        self.filename = filename
        self.parent = parent

class Parsable:
    __metaclass__ = abc.ABCMeta

    def __init__(self, context):
        self._data = []
        self._tabs = None
        self._trailing_whitespace = None
        self._attrs = {}
        self._context = context

    @abc.abstractmethod
    def parse(self):
        raise NotImplementedError()

    @property
    def parent(self):
        return self._context.parent

    def child_context(self, filename=None):
        if self._context is None:
            return None
        if filename is None:
            filename = self._context.filename
        return ParseContext(self._context.cwd, filename, self)

    @abc.abstractmethod
    def get_tabs(self):
        """ # of preceding whitespaces """
        if self._tabs is None:
            self._tabs = self.get_tabs()
        return self._tabs

    def get_data(self, include_spaces=False):
        return [elem.get_data(include_spaces) for elem in self._data]

def tab(tabs, s):
    return tabs + str(s)

class Statements(Parsable):
    def _choose_parser(self, list_):
        if not isinstance(list_, list):
            raise errors.MisconfigurationError("`parse` expects a list!")
        if len(list_) == 2 and isinstance(list_[1], list): # Bloc
            if 'server' in list_[0]:
                return ServerBloc(self.child_context())
            return Bloc(self.child_context())
        if all([isinstance(elem, str) for elem in list_]):
            if 'include' in list_:
                return Include(self.child_context())
            return Sentence(self.child_context())
        return Statements(self.child_context())

    def _parse_elem(self, list_):
        parser = self._choose_parser(list_)
        parser.parse(list_)
        return parser

    def parse(self, parse_this):
        if not isinstance(parse_this, list):
            raise errors.MisconfigurationError("Statements parsing expects a list!")
        if len(parse_this) > 0 and isinstance(parse_this[-1], str) and parse_this[-1].isspace():
            self._trailing_whitespace = parse_this[-1]
            parse_this = parse_this[:-1]
        self._data = [self._parse_elem(elem) for elem in parse_this]

    def get_tabs(self):
        if len(self._data) > 0:
            return self._data[0].get_tabs()
        return ''

    def get_data(self, include_spaces=False):
        data = super(Statements, self).get_data(include_spaces)
        if include_spaces and self._trailing_whitespace is not None:
            return data + [self._trailing_whitespace]
        return data

    def _iterate_expanded(self):
        for elem in self._data:
            if isinstance(elem, Include):
                for filename, parsed in six.iteritems(elem.parsed):
                    for sub_elem in parsed._iterate_expanded():
                        yield sub_elem
            yield elem

    def _get_thing(self, match_func):
        return filter(match_func, self._iterate_expanded())

    def _get_type(self, match_type, match_func=None):
        return self._get_thing(lambda elem: isinstance(elem, match_type) and  \
                                   (match_func is None or match_func(elem)))

    def get_thing_recursive(self, match_func):
        results = self._get_thing(match_func)
        for bloc in self._get_type(Bloc):
            results = itertools.chain(results, bloc.contents.get_thing_recursive(match_func))
        return results

    def get_directives(self, name):
        return self._get_type(Sentence, lambda sentence: sentence[0] == name)

    def _get_directive_index(self, directive, match_func=None):
        for i, elem in enumerate(self._data):
            if isinstance(elem, Sentence) and directive == elem[0] and \
                (match_func is None or match_func(elem)):
                return i
        return -1

    def contains_statement(self, statement):
        for elem in self._iterate_expanded():
            if isinstance(elem, Sentence) and elem.matches_list(statement):
                return True
        return False

    def replace_statements(self, statements):
        for statement in statements:
            found = self._get_directive_index(statement[0])
            if found < 0:
                self._add_statement(statement)
                continue
            self._data[found] = Sentence.create_from(statement, self.child_context(), self.get_tabs())

    def _add_statement(self, statement, insert_at_top=False):
        if self.contains_statement(statement):
            return
        sentence = Sentence.create_from(statement, self.child_context(), self.get_tabs())
        if insert_at_top:
            self._data.insert(0, sentence)
        else:
            self._data.append(sentence)

    def add_statements(self, statements, insert_at_top=False):
        """ doesn't expect spaces between elements in statements """
        for statement in statements:
            self._add_statement(statement, insert_at_top)

    def remove_statements(self, directive, match_func=None):
        """ doesn't expect spaces between elements in statements """
        found = self._get_directive_index(directive, match_func)
        while found >= 0:
            del self._data[found]
            found = self._get_directive_index(directive, match_func)

    @staticmethod
    def load_from(context):
        raw_parsed = []
        with open(os.path.join(context.cwd, context.filename)) as _file:
            try:
                raw_parsed = nginxparser.load_raw(_file)
            except pyparsing.ParseException as err:
                logger.debug("Could not parse file: %s due to %s", context.filename, err)
        statements = Statements(context)
        statements.parse(raw_parsed)
        return statements

def certbot_comment(preceding_spaces=1):
    return [' ' * preceding_spaces, '#', ' managed by Certbot']

def spaces_after_newline(word):
    if not word.isspace():
        return ''
    rindex = word.rfind('\n') # TODO: check \r
    return word[rindex+1:]

class Sentence(Parsable):
    def parse(self, parse_this):
        if not isinstance(parse_this, list):
            raise errors.MisconfigurationError("Sentence parsing expects a list!")
        self._data = parse_this

    @staticmethod
    def create_from(statement, context, tabs):
        """ no spaces in statement """
        spaced_statement = []
        for i in reversed(xrange(len(statement))):
            spaced_statement.insert(0, statement[i])
            if i > 0 and not statement[i].isspace() and not statement[i-1].isspace():
                spaced_statement.insert(0, ' ')
        spaced_statement.insert(0, tabs)
        if statement[0] != '#':
            spaced_statement += certbot_comment()
        result = Sentence(context)
        result.parse(spaced_statement)
        return result

    def is_comment(self):
        if len(self.words) == 0:
            return False
        return self.words[0] == '#'

    @property
    def words(self):
        def _isnt_space(x):
            return not x.isspace()
        return filter(_isnt_space, self._data)

    def matches_list(self, list_):
        for i, word in enumerate(self.words):
            if word == '#' and i == len(list_):
                return True
            if word != list_[i]:
                return False
        return True

    def __getitem__(self, index):
        return self.words[index]

    def get_data(self, include_spaces=False):
        if not include_spaces:
            return self.words
        return self._data

    def get_tabs(self):
        return spaces_after_newline(self._data[0])

class Include(Sentence):
    def parse(self, parse_this):
        super(Include, self).parse(parse_this)
        files = glob.glob(os.path.join(self._context.cwd, self.filename))
        self._attrs['parsed'] = {}
        for f in files:
            self._attrs['parsed'][f] = Statements.load_from(self.child_context(f))

    @property
    def parsed(self):
        return self._attrs['parsed']

    @property
    def filename(self):
        return self.words[1]

class Bloc(Parsable):
    def parse(self, parse_this):
        if not isinstance(parse_this, list) or len(parse_this) != 2:
            raise errors.MisconfigurationError("Bloc parsing expects a list of length 2!")
        self.names = Sentence(self.child_context())
        self.names.parse(parse_this[0]) 
        self.contents = Statements(self.child_context())
        self.contents.parse(parse_this[1]) 
        self._data = [self.names, self.contents]

    def get_tabs(self):
        return self.raw_names.get_tabs()

class ServerBloc(Bloc):
    """ This bloc should parallel a vhost! """
    def parse(self, parse_this):
        super(ServerBloc, self).parse(parse_this)
        self._process()

    def _process(self):
        self._attrs['addrs'] = set()
        self._attrs['ssl'] = False
        self._attrs['names'] = set()
        apply_ssl_to_all_addrs = False
        for listen in self.contents.get_directives('listen'):
            addr = obj.Addr.fromstring(" ".join(listen[1:]))
            if addr:
                self._attrs['addrs'].add(addr)
                if addr.ssl:
                    self._attrs['ssl'] = True

        for name in self.contents.get_directives('server_name'):
            self._attrs['names'].update(name[1:])

        for ssl in self.contents.get_directives('ssl'):
            if ssl.words[1] == 'on':
                self._attrs['ssl'] = True
                apply_ssl_to_all_addrs = True

    def as_vhost(self, filename):
        enabled = True  # We only look at enabled vhosts for now
        self._process()
        # "raw" and "path" aren't set.
        return obj.VirtualHost(filename, self.addrs, self.ssl, enabled, self.server_names, self, None)

    @property
    def addrs(self):
        return self._attrs['addrs']

    @property
    def ssl(self):
        return self._attrs['ssl']

    @property
    def server_names(self):
        return self._attrs['names']

    def duplicate(self, only_directives=None, delete_default=False):
        dup_bloc = copy.deepcopy(self)
        if only_directives is not None:
            dup_contents = dup_bloc.contents._get_type(Sentence,
                lambda directive: directive[0] in only_directives)
            dup_bloc._data[1] = dup_contents
        if delete_default:
            for directive in dup_bloc.contents.get_directives('listen'):
                if 'default_server' in directive:
                    del directive._data[directive._data.index('default_server')]
        self.parent._data.append(dup_bloc)
        return dup_bloc

class FancyParser(parser.Parser):
    def __init__(self, root_dir, config_root):
        self.parsed = {}
        self.parsed_root = None
        self.files = {}
        self.root = os.path.abspath(root_dir)
        self.config_root_filename = config_root
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
        self.parsed_root = Statements.load_from(ParseContext(self.root, self.config_root))
        self.parsed = {self.config_root: self.parsed_root}
        includes = self.parsed_root.get_thing_recursive(
                lambda sentence: isinstance(sentence, Sentence) and sentence[0] == 'include')
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
        blocs = self.parsed_root.get_thing_recursive(lambda x: isinstance(x, ServerBloc))
        for server_bloc in blocs:
            vhosts.append(server_bloc.as_vhost(server_bloc._context.filename))
        self._update_vhosts_addrs_ssl(vhosts)
        return vhosts

    def _build_global_addr_to_ssl(self):
        """Builds a map from address to whether it listens on ssl in any server block
        """
        addr_to_ssl = {}
        for filename, tree in six.iteritems(self.parsed):
            blocs = tree.get_thing_recursive(lambda x: isinstance(x, ServerBloc))
            for server_bloc in blocs:
                for addr in server_bloc.addrs:
                    addr_tuple = addr.normalized_tuple()
                    if addr_tuple not in addr_to_ssl:
                        addr_to_ssl[addr_tuple] = addr.ssl
                    addr_to_ssl[addr_tuple] = addr.ssl or addr_to_ssl[addr_tuple]
        return addr_to_ssl

    def _update_vhosts_addrs_ssl(self, vhosts):
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

    def add_server_directives(self, vhost, directives, replace, insert_at_top=False):
        """Add or replace directives in the server block identified by vhost.

        This method modifies vhost to be fully consistent with the new directives.

        ..note :: If replace is True and the directive already exists, the first
        instance will be replaced. Otherwise, the directive is added.
        ..note :: If replace is False nothing gets added if an identical
        block exists already.

        ..todo :: Doesn't match server blocks whose server_name directives are
            split across multiple conf files.

        :param :class:`~certbot_nginx.obj.VirtualHost` vhost: The vhost
            whose information we use to match on
        :param list directives: The directives to add
        :param bool replace: Whether to only replace existing directives
        :param bool insert_at_top: True if the directives need to be inserted at the top
            of the server block instead of the bottom

        """
        if not replace:
            vhost.raw.contents.add_statements(directives)
        else:
            vhost.raw.contents.replace_statements(directives)

    def remove_server_directives(self, vhost, directive_name, match_func=None):
        """Remove all directives of type directive_name.

        :param :class:`~certbot_nginx.obj.VirtualHost` vhost: The vhost
            to remove directives from
        :param string directive_name: The directive type to remove
        :param callable match_func: Function of the directive that returns true for directives
            to be deleted.
        """
        vhost.raw.contents.remove_statements(directive_name, match_func)

    def duplicate_vhost(self, vhost_template, delete_default=False, only_directives=None):
        """Duplicate the vhost in the configuration files.

        :param :class:`~certbot_nginx.obj.VirtualHost` vhost_template: The vhost
            whose information we copy
        :param bool delete_default: If we should remove default_server
            from listen directives in the block.
        :param list only_directives: If it exists, only duplicate the named directives. Only
            looks at first level of depth; does not expand includes.

        :returns: A vhost object for the newly created vhost
        :rtype: :class:`~certbot_nginx.obj.VirtualHost`
        """
        # TODO: https://github.com/certbot/certbot/issues/5185
        # put it in the same file as the template, at the same level
        dup_server_bloc = vhost_template.raw.duplicate(only_directives, delete_default)
        return dup_server_bloc.as_vhost(vhost_template.filep)

class FancyNginxParser(FancyParser):
    """Class handles the fine details of parsing the Nginx Configuration.

    :ivar str root: Normalized absolute path to the server root
        directory. Without trailing slash.
    :ivar dict parsed: Mapping of file paths to parsed trees

    """
    def __init__(self, root_dir, root_file="nginx.conf"):
        super(FancyNginxParser, self).__init__(root_dir, root_file)

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

