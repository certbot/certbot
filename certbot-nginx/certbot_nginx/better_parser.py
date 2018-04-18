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


# read-only AST thing
# so Statements is a list of Blocs and Sentences
# Blocs have a "Sentence" name and a "Statements" content
# "Sentence" is a list of words

# all of these structures hide whitespaces
# edit: "Sentence" hides whitespaces, so everything else by default also does

# thought: we're going to have to do the logic for detecting which tokens to modify anyways, so we might as well do it ahead of time.

# TODO (sydli): parser factory so these objects r immutable
# TODO (sydli): Shouldn't be throwing Misconfiguration errors everywhere. Is there a parsing error?

# class Delta:

def parse(list_):
    if not isinstance(list_, list):
        raise errors.MisconfigurationError("`parse` expects a list!")
    if len(list_) == 2 and isinstance(list_[1], list):
        if 'server' in list_[0]:
            return ServerBloc(list_)
        if 'location' in list_[0]:
            return LocationBloc(list_)
        return Bloc(list_)
    if all([isinstance(elem, str) for elem in list_]):
        if 'include' in list_:
            return Include(list_)
        return Sentence(list_)
    return Statements(list_)

class ParseContext:
    def __init__(self, cwd, filename):
        self._cwd = cwd
        self._filename = filename
    @property
    def cwd(self):
        return self._cwd
    @property
    def filename(self):
        return self._filename

class Parsable:
    __metaclass__ = abc.ABCMeta

    def __init__(self, parse_this, context):
        self._data = []
        self._tabs = None
        self._trailing_whitespace = None
        self._attrs = {}
        self._context = context
        self.parse(parse_this)

    @abc.abstractmethod
    def parse(self, lists_of_lists_of_lists):
        """ parse into fanciful tree-like structures """
        raise NotImplementedError()

    @property
    def tabs(self):
        if self._tabs is None:
            self._tabs = self.get_tabs()
        return self._tabs

    @abc.abstractmethod
    def get_tabs(self):
        """ # of preceding whitespaces """
        raise NotImplementedError()

    def get_data(self, include_spaces=False):
        return [elem.get_data(include_spaces) for elem in self._data]

def tab(tabs, s):
    return tabs + str(s)

class Statements(Parsable):
    def _parse_elem(self, list_):
        if not isinstance(list_, list):
            raise errors.MisconfigurationError("`parse` expects a list!")
        if len(list_) == 2 and isinstance(list_[1], list):
            if 'server' in list_[0]:
                return ServerBloc(list_, self._context)
            if 'location' in list_[0]:
                return LocationBloc(list_, self._context)
            return Bloc(list_, self._context)
        if all([isinstance(elem, str) for elem in list_]):
            if 'include' in list_:
                return Include(list_, self._context)
            return Sentence(list_, self._context)
        return Statements(list_, self._context)

    def parse(self, parse_this):
        if not isinstance(parse_this, list):
            raise errors.MisconfigurationError("Statements parsing expects a list!")
        if len(parse_this) > 0 and isinstance(parse_this[-1], str) and parse_this[-1].isspace():
            
            self._trailing_whitespace = parse_this[-1]
            parse_this = parse_this[:-1]
        self._data = [self._parse_elem(elem) for elem in parse_this]

    @property
    def iterate(self):
        for elem in self._data:
            if isinstance(elem, Include):
                for filename, parsed in six.iteritems(elem.parsed):
                    for sub_elem in parsed.iterate:
                        yield sub_elem
            yield elem

    # iterator
    def get_type(self, match_type, match_func=None):
        for elem in self.iterate:
            if isinstance(elem, match_type) and (match_func is None or match_func(elem)):
                yield elem

    def get_blocs(self, match_func):
        return self.get_type(Bloc, match_func)

    def get_server_blocs(self):
        server_blocs = self.get_type(ServerBloc)
        blocs = self.get_type(Bloc)
        for bloc in blocs:
            server_blocs = itertools.chain(server_blocs, bloc.contents.get_server_blocs())
        return server_blocs

    def get_sentences(self, match_func):
        return self.get_type(Sentence, match_func)

    def get_directives(self, name):
        return self.get_type(Sentence, lambda sentence: sentence[0] == name)

    def get_sentences_recursive(self, match_func, match_bloc=None):
        matches = self.get_sentences(match_func)
        blocs = self.get_blocs(match_bloc)
        for bloc in blocs:
            matches = itertools.chain(matches, bloc.contents.get_sentences_recursive(match_func, match_bloc))
        return matches

    def get_tabs(self):
        if len(self._data) > 0:
            return self._data[0].tabs
        return ''

    def get_data(self, include_spaces=False):
        data = super(Statements, self).get_data(include_spaces)
        if include_spaces and self._trailing_whitespace is not None:
            return data + [self._trailing_whitespace]
        return data

    def add_statements(self, statements):
        """ doesn't expect spaces between elements in statements """
        for statement in statements:
            spaced_statement = []
            for i in reversed(xrange(len(statement))):
                spaced_statement.append(0, statement[i])
                if i > 0 and not statement[i].isspace() and not statement[i-1].isspace():
                    spaced_statement.append(0, ' ')
            if not spaced_statement[0].isspace():
                spaced_statement.append(0, self.get_tabs())
            self._data.append(Sentence(spaced_statement))

class RootStatements(Statements):
    def __init__(self, config_dir, filename):
        raw_parsed = []
        with open(os.path.join(config_dir, filename)) as _file:
            try:
                raw_parsed = nginxparser.load_raw(_file)
            except pyparsing.ParseException as err:
                logger.debug("Could not parse file: %s due to %s", filename, err)
        super(RootStatements, self).__init__(raw_parsed, ParseContext(config_dir, filename))

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

    def is_comment(self):
        if len(self.words) == 0:
            return False
        return self.words[0] == '#'

    @property
    def words(self):
        def _isnt_space(x):
            return not x.isspace()
        return filter(_isnt_space, self._data)

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
            self._attrs['parsed'][f] = RootStatements(self._context.cwd, f)

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
        self.raw_names = Sentence(parse_this[0], self._context)
        self.raw_contents = Statements(parse_this[1], self._context)
        self._data = [self.raw_names, self.raw_contents]

    @property
    def names(self):
        return self.raw_names

    @property
    def contents(self):
        return self.raw_contents

    def get_tabs(self):
        return self.raw_names.tabs

class ServerBloc(Bloc):
    """ This bloc should parallel a vhost! """
    def parse(self, parse_this):
        super(ServerBloc, self).parse(parse_this)
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

class LocationBloc(Bloc):
    pass

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
        self.parsed_root = RootStatements(self.root, self.config_root)
        self.parsed = {self.config_root: self.parsed_root}
        includes = self.parsed_root.get_sentences_recursive(
                lambda sentence: sentence[0] == 'include',
                lambda bloc: bloc.names[0] in ['http', 'server'])
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

        """
        # Best-effort atomicity is enforced above us by reverter.py
        for filename in self.parsed:
            tree = self.parsed[filename]
            if ext:
                filename = filename + os.path.extsep + ext
            try:
                if lazy and not tree.is_dirty():
                    continue
                out = nginxparser.dumps_raw(tree.get_data(include_spaces=True))
                logger.debug('Writing nginx conf tree to %s:\n%s', filename, out)
                with open(filename, 'w') as _file:
                    _file.write(out)

            except IOError:
                logger.error("Could not open file for writing: %s", filename)

    def get_vhosts(self):
        # Note: vhost.path is only used in parser.py, so let's not use it here.
        vhosts = []
        blocs = self.parsed_root.get_server_blocs()
        for server_bloc in blocs:
            vhosts.append(server_bloc.as_vhost(server_bloc._context.filename))
        self._update_vhosts_addrs_ssl(vhosts)
        return vhosts

    def _build_global_addr_to_ssl(self):
        """Builds a map from address to whether it listens on ssl in any server block
        """
        addr_to_ssl = {}
        for filename, tree in six.iteritems(self.parsed):
            blocs = tree.get_server_blocs()
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
        pass # TODO (sydli): implement
    def remove_server_directives(self, vhost, directive_name, match_func=None):
        pass # TODO (sydli): implement
    def duplicate_vhost(self, vhost_template, delete_default=False, only_directives=None):
        pass # TODO (sydli): implement

class FancyNginxParser(FancyParser):
    """Class handles the fine details of parsing the Nginx Configuration.

    :ivar str root: Normalized absolute path to the server root
        directory. Without trailing slash.
    :ivar dict parsed: Mapping of file paths to parsed trees

    """
    def __init__(self, root_dir, root_file="nginx.conf"):
        super(FancyNginxParser, self).__init__(root_dir, root_file)

