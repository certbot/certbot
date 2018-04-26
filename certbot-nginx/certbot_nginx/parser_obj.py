"""NginxParser is a member object of the NginxConfigurator class."""
import abc
import copy
import itertools
import glob
import logging
import os
import pyparsing
import six

from certbot import errors

from certbot_nginx import nginxparser
from certbot_nginx import obj

logger = logging.getLogger(__name__)

# TODO (sydli) : Flesh out docstrings
REPEATABLE_DIRECTIVES = set(['server_name', 'listen', 'include', 'rewrite'])

class ParseContext(object):
    """ Context information held by parsed objects. """
    def __init__(self, cwd, filename, parent=None, parsed_files=None):
        self.cwd = cwd
        self.filename = filename
        self.parent = parent
        # We still need a global parsed files map so only one reference exists
        # to each individual file's parsed tree, even when expanding includes.
        if parsed_files is None:
            parsed_files = {}
        self.parsed_files = parsed_files

class WithLists(object):
    """ Abstract base class for "Parsable" objects whose underlying representation
    is a tree of lists. """

    __metaclass__ = abc.ABCMeta

    def __init__(self, context):
        self._data = []
        self._tabs = None
        self.context = context

    @abc.abstractmethod
    def parse(self, raw_list):
        """ Loads information into this object from underlying raw_list structure.
        Each Parsable object might make different assumptions about the structure of
        raw_list. """
        raise NotImplementedError()

    def child_context(self, filename=None):
        """ Spans a child context (with this object as the parent)
        """
        if self.context is None:
            return None
        if filename is None:
            filename = self.context.filename
        return ParseContext(self.context.cwd, filename, self, self.context.parsed_files)

    def get_tabs(self):
        """ Guess at the number of preceding whitespaces """
        if self._tabs is None:
            self._tabs = self.get_tabs()
        return self._tabs

    def get_data(self, include_spaces=False):
        """ Retrieves readable underlying representaiton. setting include_spaces
        to False is equivalent to the old UnspacedList object. """
        return [elem.get_data(include_spaces) for elem in self._data]

class Statements(WithLists):
    """ A group or list of "Statements". A Statement is either a Block or a Directive.
    """
    def __init__(self, context=None):
        super(Statements, self).__init__(context)
        self._trailing_whitespace = None

    # TODO; introduce parsing hooks here
    def _choose_parser(self, list_):
        if not isinstance(list_, list):
            raise errors.MisconfigurationError("`parse` expects a list!")
        if len(list_) == 2 and isinstance(list_[1], list): # Bloc
            if 'server' in list_[0]:
                return ServerBloc(self.child_context())
            return Bloc(self.child_context())
        if all([isinstance(elem, six.string_types) for elem in list_]):
            if 'include' in list_:
                return Include(self.child_context())
            return Sentence(self.child_context())
        return Statements(self.child_context())

    def _parse_elem(self, list_):
        parser = self._choose_parser(list_)
        parser.parse(list_)
        return parser

    def parse(self, parse_this):
        """ Assumes parse_this is a list of parseable lists. """
        if not isinstance(parse_this, list):
            raise errors.MisconfigurationError("Statements parsing expects a list!")
        # If there's a trailing whitespace in the list of statements, keep track of it.
        if len(parse_this) > 0 and isinstance(parse_this[-1], six.string_types) \
                               and parse_this[-1].isspace():
            self._trailing_whitespace = parse_this[-1]
            parse_this = parse_this[:-1]
        self._data = [self._parse_elem(elem) for elem in parse_this]

    def get_tabs(self):
        """ Takes a guess at the tabbing of all contained Statements-- by retrieving the
        tabbing of the first Statement."""
        if len(self._data) > 0:
            return self._data[0].get_tabs()
        return ''

    def get_data(self, include_spaces=False):
        """ TODO """
        data = super(Statements, self).get_data(include_spaces)
        if include_spaces and self._trailing_whitespace is not None:
            return data + [self._trailing_whitespace]
        return data

    def iterate_expanded(self):
        """ Generator for Statements-- and expands includes automatically.  """
        for elem in self._data:
            if isinstance(elem, Include):
                for parsed in elem.parsed.values():
                    for sub_elem in parsed.iterate_expanded():
                        yield sub_elem
            yield elem

    def _get_thing(self, match_func):
        for elem in self.iterate_expanded():
            if match_func(elem):
                yield elem

    def get_thing_shallow(self, match_func):
        """ Retrieves any Statement that returns true for match_func--
        Not recursive (so does not recurse on nested Blocs). """
        for elem in self._data:
            if match_func(elem):
                yield elem

    def get_type(self, match_type, match_func=None):
        """ Retrieve objects of a particluar type """
        return self._get_thing(lambda elem: isinstance(elem, match_type) and  \
                                   (match_func is None or match_func(elem)))

    def get_thing_recursive(self, match_func):
        """ Retrieves anything in the tree that returns true for match_func,
        also expands includes. """
        results = self._get_thing(match_func)
        for bloc in self.get_type(Bloc):
            results = itertools.chain(results, bloc.contents.get_thing_recursive(match_func))
        return results

    def get_directives(self, name):
        """ Retrieves any directive starting with |name|. Expands includes."""
        return self.get_type(Sentence, lambda sentence: sentence[0] == name)

    def _get_statement_index(self, match_func):
        """ Retrieves index of first occurrence of |directive| """
        for i, elem in enumerate(self._data):
            if isinstance(elem, Sentence) and match_func(elem):
                return i
        return -1

    def contains_exact_directive(self, statement):
        """ Returns true if |statement| is in this list of statements (+ expands includes)"""
        for elem in self.iterate_expanded():
            if isinstance(elem, Sentence) and elem.matches_list(statement):
                return True
        return False

    def _create_contextual_sentence(self, statement):
        return Sentence.create_from_context(statement, self.child_context(), self.get_tabs())

    def _create_contextual_bloc(self, statement):
        return Bloc.create_from_context(statement, self.child_context(), self.get_tabs())

    def replace_statement(self, statement, match_func, insert_at_top=False):
        """ For each statement, checks to see if an exisitng directive of that name
        exists. If so, replace the first occurrence with the statement. Otherwise, just
        add it to this object. """
        found = self._get_statement_index(match_func)
        if found < 0:
            # TODO (sydli): this level of abstraction shouldn't know about certbot_comments.
            if insert_at_top:
                self.add_statement(certbot_comment(self.context), insert_at_top)
                self.add_statement(self._create_contextual_sentence(statement), insert_at_top)
            else:
                self.add_statement(self._create_contextual_sentence(statement), insert_at_top)
                self.add_statement(certbot_comment(self.context), insert_at_top)
            return
        self._data[found] = self._create_contextual_sentence(statement)

    def add_statement(self, statement, insert_at_top=False):
        """ Adds a Statement to the end of this block of statements. """
        if insert_at_top:
            self._data.insert(0, statement)
        else:
            self._data.append(statement)

    def remove_statements(self, match_func):
        """ Removes statements from this object."""
        found = self._get_statement_index(match_func)
        while found >= 0:
            del self._data[found]
            if found < len(self._data) and isinstance(self._data[found], Sentence) and \
                    '#' in self._data[found].words and \
                    ' managed by Certbot' in self._data[found].words:
                del self._data[found]
            found = self._get_statement_index(match_func)

    @staticmethod
    def load_from(context):
        """ Creates a Statements object from the file referred to by context.
        """
        raw_parsed = []
        with open(os.path.join(context.cwd, context.filename)) as _file:
            try:
                raw_parsed = nginxparser.load_raw(_file)
            except pyparsing.ParseException as err:
                logger.debug("Could not parse file: %s due to %s", context.filename, err)
        statements = Statements(context)
        statements.parse(raw_parsed)
        context.parsed_files[context.filename] = statements
        return statements

def certbot_comment(context, preceding_spaces=4):
    """ A "Managed by Certbot" comment :) """
    result = Sentence(context)
    result.parse([' ' * preceding_spaces, '#', ' managed by Certbot'])
    return result

def spaces_after_newline(word):
    """ Retrieves number of spaces after final newline in word."""
    if not word.isspace():
        return ''
    rindex = word.rfind('\n') # TODO: check \r
    return word[rindex+1:]

class Sentence(WithLists):
    """ A list of words. Non-whitespace words are  typically separated with some
    amount of whitespace. """
    def parse(self, parse_this):
        """ Expects a list of strings.  """
        if not isinstance(parse_this, list):
            raise errors.MisconfigurationError("Sentence parsing expects a list!")
        self._data = parse_this

    @staticmethod
    def create_from_context(statement, context, tabs):
        """ Constructs an appropriately spaced statement from an unspaced one.
        no spaces in statement """
        result = Sentence(context)
        spaced_statement = _space_list(statement)
        spaced_statement.insert(0, "\n" + tabs)
        # if statement[0] != '#':
        result.parse(spaced_statement)
        return result

    def is_comment(self):
        """ Is this sentence a comment? """
        if len(self.words) == 0:
            return False
        return self.words[0] == '#'

    @property
    def words(self):
        """ Iterates over words, but without spaces. Like Unspaced List. """
        return [word.strip('"\'') for word in self._data if not word.isspace()]

    def matches_list(self, list_):
        """ Checks to see whether this object matches an unspaced list. """
        for i, word in enumerate(self.words):
            if word == '#' and i == len(list_):
                return True
            if word != list_[i]:
                return False
        return True

    def __getitem__(self, index):
        return self.words[index]

    def get_data(self, include_spaces=False):
        """ TODO """
        if not include_spaces:
            return self.words
        return self._data

    def get_tabs(self):
        """ TODO """
        return spaces_after_newline(self._data[0])

class Include(Sentence):
    """ An include statement. """
    def __init__(self, context=None):
        super(Include, self).__init__(context)
        self.parsed = None

    def parse(self, parse_this):
        """ Parsing an include touches disk-- this will fetch the associated
        files and actually parse them all! """
        super(Include, self).parse(parse_this)
        files = glob.glob(os.path.join(self.context.cwd, self.filename))
        self.parsed = {}
        for f in files:
            if f in self.context.parsed_files:
                self.parsed[f] = self.context.parsed_files[f]
            else:
                self.parsed[f] = Statements.load_from(self.child_context(f))

    @property
    def filename(self):
        """ Retrieves the filename that is being included. """
        return self.words[1]

def _space_list(list_):
    spaced_statement = []
    for i in reversed(six.moves.xrange(len(list_))):
        spaced_statement.insert(0, list_[i])
        if i > 0 and not list_[i].isspace() and not list_[i-1].isspace():
            spaced_statement.insert(0, ' ')
    return spaced_statement

class Bloc(WithLists):
    """ Any sort of bloc, denoted by a block name and curly braces. """
    def __init__(self, context=None):
        super(Bloc, self).__init__(context)
        self.names = None
        self.contents = None

    @staticmethod
    def create_from_context(raw, context, tabs):
        """ Constructs an appropriately spaced statement from an unspaced one.
        no spaces in statement """
        result = Bloc(context)
        spaced_name = _space_list(raw[0])
        spaced_name.insert(0, "\n" + tabs)
        contents = []
        for statement in raw[1]:
            spaced_statement = _space_list(statement)
            spaced_statement.insert(0, "\n" + tabs + '    ')
            contents.append(spaced_statement)
        contents.append('\n' + tabs)
        result.parse([spaced_name, contents])
        return result

    def parse(self, parse_this):
        """ Expects a list of two! """
        if not isinstance(parse_this, list) or len(parse_this) != 2:
            raise errors.MisconfigurationError("Bloc parsing expects a list of length 2!")
        self.names = Sentence(self.child_context())
        self.names.parse(parse_this[0])
        self.contents = Statements(self.child_context())
        self.contents.parse(parse_this[1])
        self._data = [self.names, self.contents]

    def get_tabs(self):
        return self.names.get_tabs()

    # TODO (sydli): contextual sentences/blocks should be parsed automatically
    # (get rid of `is_block`)
    def _add_directive(self, statement, insert_at_top=False, is_block=False):
        # pylint: disable=protected-access
        if self.contents.contains_exact_directive(statement):
            return
        if not is_block and statement[0] not in REPEATABLE_DIRECTIVES and len(
            list(self.contents.get_directives(statement[0]))) > 0:
            raise errors.MisconfigurationError("Existing %s directive conflicts with %s",
                                               statement[0], statement)
        if not is_block:
            statement = self.contents._create_contextual_sentence(statement)
            self.contents.add_statement(statement, insert_at_top)
            if statement[0] != '#':
                self.contents.add_statement(certbot_comment(self.child_context()))
            return
        statement = self.contents._create_contextual_bloc(statement)
        self.contents.add_statement(statement, insert_at_top)

    def add_directives(self, statements, insert_at_top=False, is_block=False):
        """ Add statements to this object. If the exact statement already exists,
        don't add it.

        doesn't expect spaces between elements in statements """
        if is_block:
            self._add_directive(statements, insert_at_top, is_block)
        else:
            for statement in statements:
                self._add_directive(statement, insert_at_top, is_block)

    def replace_directives(self, statements, insert_at_top=False):
        """ Adds statements to this object. For each of the statements,
        if one of this statement type already exists, replaces existing statement.
        """
        for s in statements:
            self.contents.replace_statement(s, lambda x, s=s: x[0] == s[0], insert_at_top)

    def remove_directives(self, directive, match_func=None):
        """ Removes statements from this object."""
        self.contents.remove_statements(lambda x: x[0] == directive and \
            (match_func is None or match_func(x)))


    def duplicate(self, only_directives=None, remove_singleton_listen_params=False):
        """ Duplicates iteslf into another sibling server block. """
        # pylint: disable=protected-access
        dup_bloc = copy.deepcopy(self)
        if only_directives is not None:
            dup_bloc.contents.remove_statements(lambda x: x[0] not in only_directives)
            # dup_bloc._data[1]._data = list(dup_contents)
        if remove_singleton_listen_params:
            for directive in dup_bloc.contents.get_directives('listen'):
                for word in ['default_server', 'default', 'ipv6only=on']:
                    if word in directive.words:
                        directive._data.remove(word)
        self.context.parent.add_statement(dup_bloc)
        dup_bloc.context.parent = self.context.parent
        dup_bloc._update_vhost()
        return dup_bloc


class ServerBloc(Bloc):
    """ This bloc should parallel a vhost! """

    def __init__(self, context=None):
        super(ServerBloc, self).__init__(context)
        self.addrs = set()
        self.ssl = False
        self.server_names = set()
        self.vhost = None

    def _update_vhost(self):
        self.addrs = set()
        self.ssl = False
        self.server_names = set()
        for listen in self.contents.get_directives('listen'):
            addr = obj.Addr.fromstring(" ".join(listen[1:]))
            if addr:
                self.addrs.add(addr)
                if addr.ssl:
                    self.ssl = True
        for name in self.contents.get_directives('server_name'):
            self.server_names.update(name[1:])
        for ssl in self.contents.get_directives('ssl'):
            if ssl.words[1] == 'on':
                self.ssl = True

        self.vhost.addrs = self.addrs
        self.vhost.names = self.server_names
        self.vhost.ssl = self.ssl
        self.vhost.raw = self
    def add_directives(self, statements, insert_at_top=False, is_block=False):
        super(ServerBloc, self).add_directives(statements, insert_at_top, is_block)
        self._update_vhost()
    def replace_directives(self, statements, insert_at_top=False):
        super(ServerBloc, self).replace_directives(statements, insert_at_top)
        self._update_vhost()
    def remove_directives(self, directive, match_func=None):
        super(ServerBloc, self).remove_directives(directive, match_func)
        self._update_vhost()

    def parse(self, parse_this):
        super(ServerBloc, self).parse(parse_this)
        self.vhost = obj.VirtualHost(self.context.filename if self.context is not None else "",
            self.addrs, self.ssl, True, self.server_names, self, None)
        self._update_vhost()

