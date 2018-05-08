"""NginxParser is a member object of the NginxConfigurator class."""
import abc
import logging
import six

from certbot import errors

logger = logging.getLogger(__name__)
COMMENT = ' managed by Certbot'
COMMENT_BLOCK = ['#', COMMENT]

class WithLists(object):
    """ Abstract base class for "Parsable" objects whose underlying representation
    is a tree of lists. """

    __metaclass__ = abc.ABCMeta

    def __init__(self, context):
        self._data = []
        self._tabs = None
        self.context = context

    @abc.abstractmethod
    def parse(self, raw_list, add_spaces=False):
        """ Loads information into this object from underlying raw_list structure.
        Each Parsable object might make different assumptions about the structure of
        raw_list. """
        raise NotImplementedError()

    def child_context(self, filename=None):
        """ Spans a child context (with this object as the parent)
        """
        if self.context is None:
            return ParseContext(None, None, self, None, None)
        if filename is None:
            filename = self.context.filename
        return ParseContext(self.context.cwd, filename, self, self.context.parsed_files,
                            self.context.parsing_hooks)

    @abc.abstractmethod
    def iterate(self, expanded=False, match=None):
        """ TODO
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def get_tabs(self):
        """ Guess at the number of preceding whitespaces """
        raise NotImplementedError()

    def dump(self, include_spaces=False):
        """ Retrieves readable underlying representaiton. setting include_spaces
        to False is equivalent to the old UnspacedList object. """
        return [elem.dump(include_spaces) for elem in self._data]

class Statements(WithLists):
    """ A group or list of "Statements". A Statement is either a Block or a Directive.
    """
    def __init__(self, context=None):
        super(Statements, self).__init__(context)
        self._trailing_whitespace = None

    def set_tabs(self, tabs='    '):
        """ Sets the tabbing for this set of statements.
        """
        for statement in self._data:
            statement.set_tabs(tabs)
        if self.context is not None and self.context.parent is not None:
            self._trailing_whitespace = '\n' + self.context.parent.get_tabs()

    def parse(self, parse_this, add_spaces=False):
        """ Assumes parse_this is a list of parseable lists. """
        if not isinstance(parse_this, list):
            raise errors.MisconfigurationError("Statements parsing expects a list!")
        # If there's a trailing whitespace in the list of statements, keep track of it.
        if len(parse_this) > 0 and isinstance(parse_this[-1], six.string_types) \
                               and parse_this[-1].isspace():
            self._trailing_whitespace = parse_this[-1]
            parse_this = parse_this[:-1]
        self._data = [parse_raw(elem, self.child_context(), add_spaces) for elem in parse_this]

    def get_tabs(self):
        """ Takes a guess at the tabbing of all contained Statements-- by retrieving the
        tabbing of the first Statement."""
        if len(self._data) > 0:
            return self._data[0].get_tabs()
        return ''

    def dump(self, include_spaces=False):
        """ TODO """
        data = super(Statements, self).dump(include_spaces)
        if include_spaces and self._trailing_whitespace is not None:
            return data + [self._trailing_whitespace]
        return data

    def iterate(self, expanded=False, match=None):
        """ Generator for Statements-- and expands includes automatically.  """
        for elem in self._data:
            for sub_elem in elem.iterate(expanded, match):
                yield sub_elem

    def get_type(self, match_type, match_func=None):
        """ Retrieve objects of a particluar type """
        return self.iterate(expanded=True, match=
            lambda elem: isinstance(elem, match_type) and \
                (match_func is None or match_func(elem)))

    def _get_statement_index(self, match_func):
        """ Retrieves index of first occurrence of |directive| """
        for i, elem in enumerate(self._data):
            if isinstance(elem, Sentence) and match_func(elem):
                return i
        return -1

    def replace_statement(self, statement, match_func, insert_at_top=False):
        """ For each statement, checks to see if an exisitng directive of that name
        exists. If so, replace the first occurrence with the statement. Otherwise, just
        add it to this object. """
        found = self._get_statement_index(match_func)
        if found < 0:
            self.add_statement(statement, insert_at_top)
            return
        statement = parse_raw(statement, self.child_context(), add_spaces=True)
        statement.set_tabs(self.get_tabs())
        self._data[found] = statement
        if found + 1 >= len(self._data) or not is_certbot_comment(self._data[found+1]):
            self._data.insert(found+1, certbot_comment(self.context))

    def add_statement(self, statement, insert_at_top=False):
        """ Adds a Statement to the end of this block of statements. """
        statement = parse_raw(statement, self.child_context(), add_spaces=True)
        statement.set_tabs(self.get_tabs())
        index = 0
        if insert_at_top:
            self._data.insert(0, statement)
        else:
            index = len(self._data)
            self._data.append(statement)
        if not is_comment(statement):
            self._data.insert(index+1, certbot_comment(self.context))
        return statement

    def remove_statements(self, match_func):
        """ Removes statements from this object."""
        found = self._get_statement_index(match_func)
        while found >= 0:
            del self._data[found]
            if found < len(self._data) and is_certbot_comment(self._data[found]):
                del self._data[found]
            found = self._get_statement_index(match_func)

def _spaces_after_newline(word, newline='\n'):
    """ Retrieves number of spaces after final newline in word."""
    if not word.isspace():
        return ''
    rindex = word.rfind(newline)
    return word[rindex+1:]

class Sentence(WithLists):
    """ A list of words. Non-whitespace words are  typically separated with some
    amount of whitespace. """
    def parse(self, parse_this, add_spaces=False):
        """ Expects a list of strings.  """
        if add_spaces:
            parse_this = _space_list(parse_this)
        if not isinstance(parse_this, list) or \
                any([not isinstance(elem, six.string_types) for elem in parse_this]):
            raise errors.MisconfigurationError("Sentence parsing expects a list of string types.")
        self._data = parse_this

    def iterate(self, expanded=False, match=None):
        if match is None or match(self):
            yield self

    def set_tabs(self, tabs='    ', newline='\n'):
        """ Sets the tabbing on this sentence. Inserts a newline and `tabs` at the
        beginning of `self._data`. """
        if self._data[0].isspace():
            raise errors.MisconfigurationError(
                "This sentence is already tabbed; not sure how to set the tabbing further.")
        self._data.insert(0, newline + tabs)

    # TODO: remove words usage, just use __getitem__
    @property
    def words(self):
        """ Iterates over words, but without spaces. Like Unspaced List. """
        return [word.strip('"\'') for word in self._data if not word.isspace()]

    def __getitem__(self, index):
        return self.words[index]

    def dump(self, include_spaces=False):
        """ TODO """
        if not include_spaces:
            return self.words
        return self._data

    def get_tabs(self):
        """ TODO """
        return _spaces_after_newline(self._data[0])

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

    def set_tabs(self, tabs='    '):
        """ TODO
        """
        self.names.set_tabs(tabs)
        self.contents.set_tabs(tabs + '    ')

    def iterate(self, expanded=False, match=None):
        if match is None or match(self):
            yield self
        if expanded:
            for elem in self.contents.iterate(expanded, match):
                yield elem

    def parse(self, parse_this, add_spaces=False):
        """ Expects a list of two! """
        if not is_bloc(parse_this):
            raise errors.MisconfigurationError("Bloc parsing expects a list of length 2. "
                "First element should be a list of string types (the bloc names), "
                "and second should be another list of statements (the bloc content).")
        self.names = Sentence(self.child_context())
        if add_spaces:
            parse_this[0].append(' ')
        self.names.parse(parse_this[0], add_spaces)
        self.contents = Statements(self.child_context())
        self.contents.parse(parse_this[1], add_spaces)
        self._data = [self.names, self.contents]

    def get_tabs(self):
        return self.names.get_tabs()

def is_comment(parsed_obj):
    """ Checks whether parsed_obj is a comment.
    """
    if not isinstance(parsed_obj, Sentence):
        return False
    return parsed_obj.words[0] == '#'

def is_certbot_comment(parsed_obj):
    """ Checks whether parsed_obj is a certbot comment.
    """
    if not is_comment(parsed_obj):
        return False
    if len(parsed_obj.words) != len(COMMENT_BLOCK):
        return False
    for i, word in enumerate(parsed_obj.words):
        if word != COMMENT_BLOCK[i]:
            return False
    return True

def certbot_comment(context, preceding_spaces=4):
    """ A "Managed by Certbot" comment :) """
    result = Sentence(context)
    result.parse([' ' * preceding_spaces] + COMMENT_BLOCK)
    return result

def is_bloc(list_):
    """ TODO """
    return isinstance(list_, list) and len(list_) == 2 and \
        is_sentence(list_[0]) and isinstance(list_[1], list)

def is_sentence(list_):
    """ TODO """
    return isinstance(list_, list) and all([isinstance(elem, six.string_types) for elem in list_])

def _choose_parser(child_context, list_):
    for hook, type_ in child_context.parsing_hooks:
        if hook(list_):
            return type_(child_context)
    raise errors.MisconfigurationError(
        "None of the parsing hooks succeeded, so we don't know how to parse this set of lists.")

# important functions

def parse_raw(lists_, context=None, add_spaces=False):
    """ TODO
    """
    if context is None:
        context = ParseContext("", "")
    if context.parsing_hooks is None:
        context.parsing_hooks = DEFAULT_PARSING_HOOKS
    parser = _choose_parser(context, lists_)
    parser.parse(lists_, add_spaces)
    return parser

DEFAULT_PARSING_HOOKS = (
    (is_bloc, Bloc),
    (is_sentence, Sentence),
    (lambda list_: isinstance(list_, list), Statements)
)

class ParseContext(object):
    """ Context information held by parsed objects. """
    def __init__(self, cwd, filename, parent=None, parsed_files=None,
                 parsing_hooks=DEFAULT_PARSING_HOOKS):
        self.parsing_hooks = parsing_hooks
        self.cwd = cwd
        self.filename = filename
        self.parent = parent
        # We still need a global parsed files map so only one reference exists
        # to each individual file's parsed tree, even when expanding includes.
        if parsed_files is None:
            parsed_files = {}
        self.parsed_files = parsed_files

