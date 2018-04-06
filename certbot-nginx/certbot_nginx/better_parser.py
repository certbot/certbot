"""NginxParser is a member object of the NginxConfigurator class."""
import abc
import copy
import functools
import glob
import logging
import os
import pyparsing
import re

import six

from certbot import errors

from certbot_nginx import nginxparser

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
        return Sentence(list_)
    return Statements(list_)

class Parsable:
    __metaclass__ = abc.ABCMeta

    def __init__(self, parse_this):
        self._data = []
        self._tabs = None
        self._trailing_whitespace = None
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
    def parse(self, parse_this):
        if not isinstance(parse_this, list):
            raise MisconfigurationError("Statements parsing expects a list!")
        if len(parse_this) > 0 and isinstance(parse_this[-1], str) and parse_this[-1].isspace():
            
            self._trailing_whitespace = parse_this[-1]
            parse_this = parse_this[:-1]
        self._data = [parse(elem) for elem in parse_this]

    def get_type(self, match_type, match_func=None):
        def _match(elem):
            return isinstance(elem, match_type) and (match_func is None or match_func(elem))
        return filter(_match, self._data)

    def get_blocs(self, match_func):
        return self.get_type(Bloc, match_func)

    def get_sentences(self, match_func):
        return self.get_type(Sentence, match_func)

    def get_sentences_recursive(self, match_func, match_bloc=None):
        matches = self.get_sentences(match_func)
        blocs = self.get_blocs(match_bloc)
        for bloc in blocs:
            matches = matches + bloc.contents.get_sentences_recursive(match_func, match_bloc)
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

def spaces_after_newline(word):
    if not word.isspace():
        return ''
    rindex = word.rfind('\n') # TODO: check \r
    return word[rindex+1:]

class Sentence(Parsable):
    def parse(self, parse_this):
        if not isinstance(parse_this, list):
            raise MisconfigurationError("Sentence parsing expects a list!")
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

class Bloc(Parsable):
    def parse(self, parse_this):
        if not isinstance(parse_this, list) or len(parse_this) != 2:
            raise MisconfigurationError("Bloc parsing expects a list of length 2!")
        self.raw_names = Sentence(parse_this[0])
        self.raw_contents = Statements(parse_this[1])
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
    pass

class LocationBloc(Bloc):
    pass

class FancyParser(object):
    def __init__(self, root_dir, config_root):
        self.parsed = {}
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
        self.parsed = {}
        # TODO: make trees a Statements datastructure also
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
            if not isinstance(tree, Statements):
                raise errors.Misconfiguration("oh no, that's not right")
            includes = tree.get_sentences_recursive(
                lambda sentence: sentence[0] == 'include',
                lambda bloc: bloc.names[0] in ['http', 'server'])
            for include in includes:
                self._parse_recursively(include[1])

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
                    parsed = parse(nginxparser.load_raw(_file)) # DOUBLE PARSE
                    self.parsed[item] = parsed
                    trees.append(parsed)
            except IOError:
                logger.warning("Could not open file: %s", item)
            except pyparsing.ParseException as err:
                logger.debug("Could not parse file: %s due to %s", item, err)
        return trees


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

class FancyNginxParser(FancyParser):
    """Class handles the fine details of parsing the Nginx Configuration.

    :ivar str root: Normalized absolute path to the server root
        directory. Without trailing slash.
    :ivar dict parsed: Mapping of file paths to parsed trees

    """
    def __init__(self, root_dir):
        super(FancyNginxParser, self).__init__(root_dir, "nginx.conf")

