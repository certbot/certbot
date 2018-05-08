""" This file contains parsing routines and object classes to help derive meaning from
raw lists of tokens from pyparsing. """

import abc
import logging
import six

from certbot import errors

logger = logging.getLogger(__name__)
COMMENT = ' managed by Certbot'
COMMENT_BLOCK = ['#', COMMENT]

class WithLists(object):
    """ Abstract base class for "Parsable" objects whose underlying representation
    is a tree of lists.

    :param .ParseContext context: Contains contextual information that this object may need
        to perform parsing and dumping operations properly.
    """

    __metaclass__ = abc.ABCMeta

    def __init__(self, context):
        self._data = []
        self._tabs = None
        self.context = context

    @abc.abstractmethod
    def parse(self, raw_list, add_spaces=False):
        """ Loads information into this object from underlying raw_list structure.
        Each Parsable object might make different assumptions about the structure of
        raw_list.

        :param list raw_list: A list or sublist of tokens from pyparsing, containing whitespace
            as separate tokens.
        :param bool add_spaces: If set, the method can and should manipulate and insert spacing
            between non-whitespace tokens and lists to delimit them.
        :raises .errors.MisconfigurationError: when the assumptions about the structure of
            raw_list are not met.
        """
        raise NotImplementedError()

    def child_context(self, filename=None):
        """ Spans a child context (with this object as the parent).
        :param str filename:    If set, creates a context with a new filename.
            This can be helpful if a context "changes" files-- for instance, via an
            'Include' directive of some sort.  """
        if self.context is None:
            # This is really only for testing purposes. The context should otherwise never
            # be set to None.
            return ParseContext(None, None, self, None, None)
        if filename is None:
            filename = self.context.filename
        return ParseContext(self.context.cwd, filename, self, self.context.parsed_files,
                            self.context.parsing_hooks)

    @abc.abstractmethod
    def iterate(self, expanded=False, match=None):
        """ Iterates across this object. If this object is a leaf object, only yields
        itself. If it contains references other parsing objects, and `expanded` is set,
        this function should first yield itself, then recursively iterate across all of them.
        :param bool expanded: Whether to recursively iterate on possible children.
        :param callable match: If provided, an object is only iterated if this callable
            returns True when called on that object.

        :returns: Iterator over desired objects.
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def get_tabs(self):
        """ Guess at the tabbing style of this parsed object, based on whitespace.

        If this object is a leaf, it deducts the tabbing based on its own contents.
        Other objects may guess by calling `get_tabs` recursively on child objects.

        :returns: Guess at tabbing for this object. Should only return whitespace strings
            that does not contain newlines.
        :rtype str:
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def set_tabs(self, tabs='    '):
        """This tries to set and alter the tabbing of the current object to a desired
        whitespace string. Primarily meant for objects that were constructed, so they
        can conform to surrounding whitespace.

        :param str tabs: A whitespace string (not containing newlines).
        """
        raise NotImplementedError()

    def dump(self, include_spaces=False):
        """ Dumps back to pyparsing-like list tree. The opposite of `parse`.

        Note: if this object has not been modified, `dump` with `include_spaces=True`
        should always return the original input of `parse`.

        :param bool include_spaces: If set to False, magically hides whitespace tokens from
            dumped output.

        :returns: Pyparsing-like list tree.
        :rtype list:
        """
        return [elem.dump(include_spaces) for elem in self._data]

class Statements(WithLists):
    """ A group or list of "Statements". A Statement is either a Block or a Sentence.

    The underlying representation is simply a list of these Statement objects, with
    an extra `_trailing_whitespace` string to keep track of the whitespace that does not
    precede any more statements.
    """
    def __init__(self, context=None):
        super(Statements, self).__init__(context)
        self._trailing_whitespace = None

    # ======== Begin overridden functions

    def set_tabs(self, tabs='    '):
        """ Sets the tabbing for this set of statements. Does this by calling `set_tabs`
        on each of the child statements.

        Then, if a parent is present, sets trailing whitespace to parent tabbing. This
        is so that the trailing } of any Block that contains Statements lines up
        with parent tabbing.
        """
        for statement in self._data:
            statement.set_tabs(tabs)
        if self.context is not None and self.context.parent is not None:
            self._trailing_whitespace = '\n' + self.context.parent.get_tabs()

    def parse(self, parse_this, add_spaces=False):
        """ Parses a list of statements.
        Expects all elements in `parse_this` to be parseable by `context.parsing_hooks`,
        with an optional whitespace string at the last index of `parse_this`.
        """
        if not isinstance(parse_this, list):
            raise errors.MisconfigurationError("Statements parsing expects a list!")
        # If there's a trailing whitespace in the list of statements, keep track of it.
        if len(parse_this) > 0 and isinstance(parse_this[-1], six.string_types) \
                               and parse_this[-1].isspace():
            self._trailing_whitespace = parse_this[-1]
            parse_this = parse_this[:-1]
        self._data = [parse_raw(elem, self.child_context(), add_spaces) for elem in parse_this]

    def get_tabs(self):
        """ Takes a guess at the tabbing of all contained Statements by retrieving the
        tabbing of the first Statement."""
        if len(self._data) > 0:
            return self._data[0].get_tabs()
        return ''

    def dump(self, include_spaces=False):
        """ Dumps this object by first dumping each statement, then appending its
        trailing whitespace (if `include_spaces` is set) """
        data = super(Statements, self).dump(include_spaces)
        if include_spaces and self._trailing_whitespace is not None:
            return data + [self._trailing_whitespace]
        return data

    def iterate(self, expanded=False, match=None):
        """ Combines each statement's iterator.  """
        for elem in self._data:
            for sub_elem in elem.iterate(expanded, match):
                yield sub_elem

    # ======== End overridden functions

    def get_type(self, match_type, match_func=None):
        """ Retrieve statements of a particular class type.

        :param type match_type: The type to match.
        :param callable match_func: If set, will only return type matches that
            also pass this match function.

        :returns: An iterator over matching statements.
        """
        return self.iterate(expanded=True, match=
            lambda elem: isinstance(elem, match_type) and \
                (match_func is None or match_func(elem)))

    def _get_statement_index(self, match_func):
        """ Retrieves index of first occurrence of a statement which matches `match_func`.
        :param callable match_func: A function that accepts a statement as a param and
            returns a boolean-- whether a particular statement "matches".

        :returns: The index of the matching statement.
        :rtype int:
        """
        for i, elem in enumerate(self._data):
            if isinstance(elem, Sentence) and match_func(elem):
                return i
        return -1

    def replace_statement(self, statement, match_func, insert_at_top=False):
        """ Checks to see if an existing statement matches `match_func`.
        If so, replace the first matching statement with `statement`. Otherwise, just
        add it to this Statements object.

        We ensure that this statement is followed by an informative "managed by Certbot"
        comment, but is not followed by duplicates.

        :param list statement: Raw statement to add or replace. This statement will be parsed.
        :param callable match_func: A function to find the statement to replace.
        :param bool insert_at_top: If we couldn't find a statement to replace,
            `insert_at_top` determines whether `statement` is added to the top of this
            block or the end.

        :returns: The parsed and replaced/added Statement.
        """
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
        """ Parses and adds a statement to this block of statements.

        We ensure that this statement is followed by an informative "managed by Certbot"
        comment.

        :param list statement: Raw statement to add. This statement will be parsed.
        :param bool insert_at_top: Determines whether this statement is added to the top
            of this block or the end.

        :returns: The parsed and added Statement.
        """
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
        """ Removes statements from this object that are matched.

        If a removed statement is followed by a "managed by Certbot" comment, the comment is
        also removed.

        :param callable match_func: A function to determine which statements to remove."""
        found = self._get_statement_index(match_func)
        while found >= 0:
            del self._data[found]
            if found < len(self._data) and is_certbot_comment(self._data[found]):
                del self._data[found]
            found = self._get_statement_index(match_func)

def _space_list(list_):
    """ Inserts whitespace between adjacent non-whitespace tokens. """
    spaced_statement = []
    for i in reversed(six.moves.xrange(len(list_))):
        spaced_statement.insert(0, list_[i])
        if i > 0 and not list_[i].isspace() and not list_[i-1].isspace():
            spaced_statement.insert(0, ' ')
    return spaced_statement

class Sentence(WithLists):
    """ A list of words. Non-whitespace words are typically separated with whitespace tokens. """

    # ======== Begin overridden functions

    def parse(self, parse_this, add_spaces=False):
        """ Parses a list of string types into this object.
        If add_spaces is set, adds whitespace tokens between adjacent non-whitespace tokens."""
        if add_spaces:
            parse_this = _space_list(parse_this)
        if not isinstance(parse_this, list) or \
                any([not isinstance(elem, six.string_types) for elem in parse_this]):
            raise errors.MisconfigurationError("Sentence parsing expects a list of string types.")
        self._data = parse_this

    def iterate(self, expanded=False, match=None):
        """ Simply yields itself. """
        if match is None or match(self):
            yield self

    def set_tabs(self, tabs='    '):
        """ Sets the tabbing on this sentence. Inserts a newline and `tabs` at the
        beginning of `self._data`. """
        if self._data[0].isspace():
            raise errors.MisconfigurationError(
                "This sentence is already tabbed; not sure how to set the tabbing further.")
        self._data.insert(0, tabs)

    def dump(self, include_spaces=False):
        """ Dumps this sentence. If include_spaces is set, includes whitespace tokens."""
        if not include_spaces:
            return self.words
        return self._data

    def get_tabs(self):
        """ Guesses at the tabbing of this sentence. If the first element is whitespace,
        returns the whitespace after the rightmost newline in the string. """
        first = self._data[0]
        if not first.isspace():
            return ''
        rindex = first.rfind('\n')
        return first[rindex+1:]

    # ======== End overridden functions

    @property
    def words(self):
        """ Iterates over words, but without spaces. Like Unspaced List. """
        return [word.strip('"\'') for word in self._data if not word.isspace()]

    def __getitem__(self, index):
        return self.words[index]

class Bloc(WithLists):
    """ Any sort of bloc, denoted by a block name and curly braces, like so:
    The parsed block:
        block name {
            content 1;
            content 2;
        }
    might be represented with the list [names, contents], where
        names = ['block', ' ', 'name', ' ']
        contents = [['\n    ', 'content', ' ', '1'], ['\n    ', 'content', ' ', '2'], '\n']
    """
    def __init__(self, context=None):
        super(Bloc, self).__init__(context)
        self.names = None
        self.contents = None

    def set_tabs(self, tabs='    '):
        """ Sets tabs by setting equivalent tabbing on names, then adding tabbing
        to contents."""
        self.names.set_tabs(tabs)
        self.contents.set_tabs(tabs + '    ')

    def iterate(self, expanded=False, match=None):
        """ Iterator over self, and if expanded is set, over its contents. """
        if match is None or match(self):
            yield self
        if expanded:
            for elem in self.contents.iterate(expanded, match):
                yield elem

    def parse(self, parse_this, add_spaces=False):
        """ Parses a list that resembles a block.

        The assumptions that this routine makes are:
            1. the first element of `parse_this` is a valid Sentence.
            2. the second element of `parse_this` is a valid Statement.
        If add_spaces is set, we call it recursively on `names` and `contents`, and
        add an extra trailing space to `names` (to separate the block's opening bracket
        and the block name).
        """
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
        """ Guesses tabbing by retrieving tabbing guess of self.names. """
        return self.names.get_tabs()

def is_comment(parsed_obj):
    """ Checks whether parsed_obj is a comment.

    :param .WithLists parsed_obj:

    :returns: whether parsed_obj represents a comment sentence.
    :rtype bool:
    """
    if not isinstance(parsed_obj, Sentence):
        return False
    return parsed_obj.words[0] == '#'

def is_certbot_comment(parsed_obj):
    """ Checks whether parsed_obj is a "managed by Certbot" comment.

    :param .WithLists parsed_obj:

    :returns: whether parsed_obj is a "managed by Certbot" comment.
    :rtype bool:
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
    """ A "Managed by Certbot" comment.
    :param int preceding_spaces: Number of spaces between the end of the previous
        statement and the comment.
    :returns: Sentence containing the comment.
    :rtype: .Sentence
    """
    result = Sentence(context)
    result.parse([' ' * preceding_spaces] + COMMENT_BLOCK)
    return result

def is_bloc(list_):
    """ Returns True if `list_` can be parseable as a `Bloc`-- that is,
    it's got a length of 2, the first element is a `Sentence` and the second can be
    a `Statements`.

    :param list list_: The raw unparsed list to check.

    :returns: whether this list_ is parseable by `Bloc`. """
    return isinstance(list_, list) and len(list_) == 2 and \
        is_sentence(list_[0]) and isinstance(list_[1], list)

def is_sentence(list_):
    """ Returns True if `list_` can be parseable as a `Sentence`-- that is,
    every element is a string type.

    :param list list_: The raw unparsed list to check.

    :returns: whether this list_ is parseable by `Sentence`.
    """
    return isinstance(list_, list) and all([isinstance(elem, six.string_types) for elem in list_])

def _choose_parser(child_context, list_):
    """ Choose a parser from child_context, based on whichever hook returns True first. """
    for hook, type_ in child_context.parsing_hooks:
        if hook(list_):
            return type_(child_context)
    raise errors.MisconfigurationError(
        "None of the parsing hooks succeeded, so we don't know how to parse this set of lists.")

def parse_raw(lists_, context=None, add_spaces=False):
    """ Primary parsing factory function. Based on `context.parsing_hooks`, chooses
    WithLists objects with which it recursively parses `lists_`.
    :param list lists_: raw lists from pyparsing to parse.
    :param .ParseContext context: Context containing parsing hooks. If not set,
        uses default parsing hooks.
    :param bool add_spaces: Whether to pass add_spaces to the parser.

    :raises errors.MisconfigurationError: If no parsing hook passes, and we can't
        determine which type to parse the raw lists into.
    """
    if context is None:
        context = ParseContext("", "")
    if context.parsing_hooks is None:
        context.parsing_hooks = DEFAULT_PARSING_HOOKS
    parser = _choose_parser(context, lists_)
    parser.parse(lists_, add_spaces)
    return parser

# Default set of parsing hooks. By default, lists go to Statements.
DEFAULT_PARSING_HOOKS = (
    (is_bloc, Bloc),
    (is_sentence, Sentence),
    (lambda list_: isinstance(list_, list), Statements)
)

class ParseContext(object):
    """ Context information held by parsed objects.

    :param str cwd: current working directory containing file that the associated object
        was parsed from (and will dump to)
    :param str filename: relative filename located within `cwd` of file that the associated
        object was parsed from (and will dump to)
    :param .WithLists parent: The parent object containing the associated object.
    :param dict parsed_files: A global containing all parsed files, so parsing
        routines don't re-parse files.
    :param tuple parsing_hooks: Parsing information for `parse_raw`.
    """
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

