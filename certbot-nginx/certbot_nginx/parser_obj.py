"""NginxParser is a member object of the NginxConfigurator class."""
import abc
import copy
import itertools
import glob
import logging
import os
import pyparsing

from certbot import errors

from certbot_nginx import nginxparser
from certbot_nginx import obj

logger = logging.getLogger(__name__)

# TODO (sydli) : Flesh out docstrings

class ParseContext(object):
    """ Context information held by parsed objects. """
    def __init__(self, cwd, filename, parent=None):
        self.cwd = cwd
        self.filename = filename
        self.parent = parent

class Parsable(object):
    """ Abstract base class for "Parsable" objects whose underlying representation
    is stored in data. """

    __metaclass__ = abc.ABCMeta

    def __init__(self, context):
        self.data = []
        self._tabs = None
        self._context = context

    @abc.abstractmethod
    def parse(self, raw_list):
        """ Loads information into this object from underlying raw_list structure.
        Each Parsable object might make different assumptions about the structure of
        raw_list. """
        raise NotImplementedError()

    @property
    def parent(self):
        """ The object containing this one. If None, thne this object is the root.
        """
        return self._context.parent

    @property
    def filename(self):
        """ The file that contains this object definition.
        """
        return self._context.filename

    def child_context(self, filename=None):
        """ Spans a child context (with this object as the parent)
        """
        if self._context is None:
            return None
        if filename is None:
            filename = self._context.filename
        return ParseContext(self._context.cwd, filename, self)

    @abc.abstractmethod
    def get_tabs(self):
        """ Guess at the number of preceding whitespaces """
        if self._tabs is None:
            self._tabs = self.get_tabs()
        return self._tabs

    def get_data(self, include_spaces=False):
        """ Retrieves readable underlying representaiton. setting include_spaces
        to False is equivalent to the old UnspacedList object. """
        return [elem.get_data(include_spaces) for elem in self.data]

class Statements(Parsable):
    """ A group or list of "Statements". A Statement is either a Block or a Directive.
    """
    def __init__(self, context=None);
        super(Statements, self).__init__(context)
        self._trailing_whitespace = None

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
        """ Assumes parse_this is a list of parseable lists. """
        if not isinstance(parse_this, list):
            raise errors.MisconfigurationError("Statements parsing expects a list!")
        if len(parse_this) > 0 and isinstance(parse_this[-1], str) and parse_this[-1].isspace():
            self._trailing_whitespace = parse_this[-1]
            parse_this = parse_this[:-1]
        self.data = [self._parse_elem(elem) for elem in parse_this]

    def get_tabs(self):
        """ Takes a guess at the tabbing of all contained Statements-- by retrieving the
        tabbing of the first Statement."""
        if len(self.data) > 0:
            return self.data[0].get_tabs()
        return ''

    def get_data(self, include_spaces=False):
        """ TODO """
        data = super(Statements, self).get_data(include_spaces)
        if include_spaces and self._trailing_whitespace is not None:
            return data + [self._trailing_whitespace]
        return data

    def iterate_expanded(self):
        """ Generator for Statements-- and expands includes automatically.  """
        for elem in self.data:
            if isinstance(elem, Include):
                for parsed in elem.parsed.values():
                    for sub_elem in parsed.iterate_expanded():
                        yield sub_elem
            yield elem

    def _get_thing(self, match_func):
        return filter(match_func, self.iterate_expanded())

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

    def _get_directive_index(self, directive, match_func=None):
        """ Retrieves index of first occurrence of |directive| """
        for i, elem in enumerate(self.data):
            if isinstance(elem, Sentence) and directive == elem[0] and \
                (match_func is None or match_func(elem)):
                return i
        return -1

    def contains_statement(self, statement):
        """ Returns true if |statement| is in this list of statements (+ expands includes)"""
        for elem in self.iterate_expanded():
            if isinstance(elem, Sentence) and elem.matches_list(statement):
                return True
        return False

    def replace_statements(self, statements):
        """ For each statement, checks to see if an exisitng directive of that name
        exists. If so, replace the first occurrence with the statement. Otherwise, just
        add it to this object. """
        for statement in statements:
            found = self._get_directive_index(statement[0])
            if found < 0:
                self._add_statement(statement)
                continue
            self.data[found] = Sentence.create_from(statement,
                self.child_context(), self.get_tabs())

    def _add_statement(self, statement, insert_at_top=False):
        if self.contains_statement(statement):
            return
        sentence = Sentence.create_from(statement, self.child_context(), self.get_tabs())
        if insert_at_top:
            self.data.insert(0, sentence)
        else:
            self.data.append(sentence)

    def add_statements(self, statements, insert_at_top=False):
        """ Add statements to this object. If the exact statement already exists,
        don't add it.

        doesn't expect spaces between elements in statements """
        for statement in statements:
            self._add_statement(statement, insert_at_top)

    def remove_statements(self, directive, match_func=None):
        """ Removes statements from this object.
        TODO (sydli): ensure comment removal works.
        doesn't expect spaces between elements in statements """
        found = self._get_directive_index(directive, match_func)
        while found >= 0:
            del self.data[found]
            found = self._get_directive_index(directive, match_func)

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
        return statements

def certbot_comment(preceding_spaces=1):
    """ A "Managed by Certbot" comment :) """
    return [' ' * preceding_spaces, '#', ' managed by Certbot']

def spaces_after_newline(word):
    """ Retrieves number of spaces after final newline in word."""
    if not word.isspace():
        return ''
    rindex = word.rfind('\n') # TODO: check \r
    return word[rindex+1:]

class Sentence(Parsable):
    """ A list of words. Non-whitespace words are  typically separated with some
    amount of whitespace. """
    def parse(self, parse_this):
        """ Expects a list of strings.  """
        if not isinstance(parse_this, list):
            raise errors.MisconfigurationError("Sentence parsing expects a list!")
        self.data = parse_this

    @staticmethod
    def create_from(statement, context, tabs):
        """ Constructs an appropriately spaced statement from an unspaced one.
        no spaces in statement """
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
        """ Is this sentence a comment? """
        if len(self.words) == 0:
            return False
        return self.words[0] == '#'

    @property
    def words(self):
        """ Iterates over words, but without spaces. Like Unspaced List. """
        def _isnt_space(x):
            return not x.isspace()
        return filter(_isnt_space, self.data)

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
        return self.data

    def get_tabs(self):
        """ TODO """
        return spaces_after_newline(self.data[0])

class Include(Sentence):
    """ An include statement. """
    def __init__(self, context=None):
        super(Include, self).__init__(context)
        self.parsed = None

    def parse(self, parse_this):
        """ Parsing an include touches disk-- this will fetch the associated
        files and actually parse them all! """
        super(Include, self).parse(parse_this)
        files = glob.glob(os.path.join(self._context.cwd, self.filename))
        self.parsed = {}
        for f in files:
            self.parsed[f] = Statements.load_from(self.child_context(f))

    @property
    def filename(self):
        return self.words[1]

class Bloc(Parsable):
    """ Any sort of bloc, denoted by a block name and curly braces. """
    def __init__(self, context=None):
        super(Bloc, self).__init__(context)
        self.names = None
        self.contents = None

    def parse(self, parse_this):
        """ Expects a list of two! """
        if not isinstance(parse_this, list) or len(parse_this) != 2:
            raise errors.MisconfigurationError("Bloc parsing expects a list of length 2!")
        self.names = Sentence(self.child_context())
        self.names.parse(parse_this[0])
        self.contents = Statements(self.child_context())
        self.contents.parse(parse_this[1])
        self.data = [self.names, self.contents]

    def get_tabs(self):
        return self.names.get_tabs()

class ServerBloc(Bloc):
    """ This bloc should parallel a vhost! """
    def __init__(self, context=None):
        super(ServerBloc, self).__init__(context)
        self.addrs = set()
        self.ssl = False
        self.server_names = set()

    def parse(self, parse_this):
        super(ServerBloc, self).parse(parse_this)
        self._process()

    def _process(self):
        # TODO (sydli): use apply_ssl_to_all_addrs
        self.addrs = set()
        self.ssl = False
        self.server_names = set()
        # apply_ssl_to_all_addrs = False
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
                # apply_ssl_to_all_addrs = True

    def as_vhost(self, filename):
        """ Transform this object into a parallel vhost object
        We might be able to consolidate the two, instead of maintaining separate
        data structures.
        """
        enabled = True  # We only look at enabled vhosts for now
        self._process()
        # "raw" and "path" aren't set.
        return obj.VirtualHost(filename, self.addrs, self.ssl, enabled,
                               self.server_names, self, None)

    def duplicate(self, only_directives=None, delete_default=False):
        """ Duplicates iteslf into another sibling server block. """
        dup_bloc = copy.deepcopy(self)
        if only_directives is not None:
            dup_contents = dup_bloc.contents.get_type(Sentence,
                lambda directive: directive[0] in only_directives)
            dup_bloc.data[1] = dup_contents
        if delete_default:
            for directive in dup_bloc.contents.get_directives('listen'):
                if 'default_server' in directive:
                    del directive.data[directive.data.index('default_server')]
        self.parent.data.append(dup_bloc)
        return dup_bloc

