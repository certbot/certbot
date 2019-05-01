""" This file contains parsing routines and object classes to help derive meaning from
raw lists of tokens from pyparsing. """

import abc
import logging
import six

from certbot import errors

from certbot_nginx import nginxparser

from acme.magic_typing import List # pylint: disable=unused-import, no-name-in-module

logger = logging.getLogger(__name__)
COMMENT = " managed by Certbot"
COMMENT_BLOCK = ["#", COMMENT]


class Parsable(object):
    """ Abstract base class for "Parsable" objects whose underlying representation
    is a tree of lists.

    :param .ParseContext context: This object's context
    """

    __metaclass__ = abc.ABCMeta

    def __init__(self, context=None):
        self._data = [] # type: List[object]
        self.context = context

    def get_parent(self):
        if self.context == None:
            return None
        return self.context.parent

    @staticmethod
    @abc.abstractmethod
    def should_parse(lists):
        """ Returns whether the contents of `lists` can be parsed into this object.

        :returns: Whether `lists` can be parsed as this object.
        :rtype bool:
        """
        raise NotImplementedError()

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

    def dump_unspaced_list(self):
        """ Dumps back to pyparsing-like list tree into an UnspacedList.
        Use for compatibility with UnspacedList dependencies while migrating
        to new parsing objects.

        :returns: Pyparsing-like list tree.
        :rtype :class:`.nginxparser.UnspacedList`:
        """
        return nginxparser.UnspacedList(self.dump(True))


    def child_context(self, filename=None, cwd=None):
        """ Spawn a child context. """
        if self.context:
            return self.context.child(self, filename=filename)
        return ParseContext(parent=self, filename=filename, cwd=cwd)

    def get_path(self):
        """ TODO: document and test"""
        if not self.context.parent or self.context.parent.context.filename != self.context.filename:
            return None
        parent_path = self.context.parent.get_path()
        my_index = self.context.parent._data.index(self)
        if parent_path:
            return parent_path + [my_index]
        return [my_index]

class Directives(Parsable):
    """ A group or list of Directives.

    The underlying representation is simply a list of other parsed objects, with
    an extra `_trailing_whitespace` string to keep track of the whitespace that does not
    precede any more statements.
    """
    def __init__(self, context=None):
        super(Directives, self).__init__(context)
        self._trailing_whitespace = None

    # ======== Begin overridden functions

    @staticmethod
    def should_parse(lists):
        return isinstance(lists, list)

    def parse(self, raw_list, add_spaces=False):
        """ Parses a list of statements.
        Expects all elements in `raw_list` to be parseable by `type(self).parsing_hooks`,
        with an optional whitespace string at the last index of `raw_list`.
        """
        if isinstance(raw_list, nginxparser.UnspacedList):
            raw_list = raw_list.spaced
        if not isinstance(raw_list, list):
            raise errors.MisconfigurationError("Directives parsing expects a list!")
        # If there's a trailing whitespace in the list of statements, keep track of them
        if raw_list:
            i = -1
            while len(raw_list) >= -i and isinstance(raw_list[i], six.string_types) and raw_list[i].isspace():
                i -= 1
            self._trailing_whitespace = "".join(raw_list[i+1:])
            raw_list = raw_list[:i+1]
        # Create parsing objects first, then parse. Then references to parent
        # data exist while we parse the child objects.
        self._data = [_choose_parser(self.child_context(), elem) for elem in raw_list]
        for i, elem in enumerate(raw_list):
            self._data[i].parse(elem, add_spaces)

    def dump(self, include_spaces=False):
        """ Dumps this object by first dumping each statement, then appending its
        trailing whitespace (if `include_spaces` is set) """
        data = super(Directives, self).dump(include_spaces)
        if include_spaces and self._trailing_whitespace is not None:
            return data + [self._trailing_whitespace]
        return data

    def iterate(self, expanded=False, match=None):
        """ Combines each statement's iterator.  """
        for elem in self._data:
            for sub_elem in elem.iterate(expanded, match):
                yield sub_elem

    # ======== End overridden functions

    def get_type(self, match_type):
        """ TODO
        """
        return self.iterate(expanded=True,
            match=lambda elem: isinstance(elem, match_type))


def _space_list(list_):
    """ Inserts whitespace between adjacent non-whitespace tokens. """
    spaced_statement = [] # type: List[str]
    for i in reversed(six.moves.xrange(len(list_))):
        spaced_statement.insert(0, list_[i])
        if i > 0 and not list_[i].isspace() and not list_[i-1].isspace():
            spaced_statement.insert(0, " ")
    return spaced_statement


class Sentence(Parsable):
    """ A list of words. Non-whitespace words are typically separated with whitespace tokens. """

    # ======== Begin overridden functions

    @staticmethod
    def should_parse(lists):
        """ Returns True if `lists` can be parseable as a `Sentence`-- that is,
        every element is a string type.

        :param list lists: The raw unparsed list to check.

        :returns: whether this lists is parseable by `Sentence`.
        """
        return isinstance(lists, list) and len(lists) > 0 and \
            all([isinstance(elem, six.string_types) for elem in lists])

    def parse(self, raw_list, add_spaces=False):
        """ Parses a list of string types into this object.
        If add_spaces is set, adds whitespace tokens between adjacent non-whitespace tokens."""
        if add_spaces:
            raw_list = _space_list(raw_list)
        if not isinstance(raw_list, list) or \
                any([not isinstance(elem, six.string_types) for elem in raw_list]):
            raise errors.MisconfigurationError("Sentence parsing expects a list of string types.")
        self._data = raw_list

    def iterate(self, expanded=False, match=None):
        """ Simply yields itself. """
        if (match is None) or match(self):
            yield self

    def dump(self, include_spaces=False):
        """ Dumps this sentence. If include_spaces is set, includes whitespace tokens."""
        if not include_spaces:
            return self.words
        return self._data

    # ======== End overridden functions

    @property
    def words(self):
        """ Iterates over words, but without spaces. Like Unspaced List. """
        return [word.strip("\"\'") for word in self._data if not word.isspace()]

    def __len__(self):
        return len(self.words)

    def __getitem__(self, index):
        return self.words[index]

    def __contains__(self, word):
        return word in self.words


class Block(Parsable):
    """ Any sort of bloc, denoted by a block name and curly braces, like so:
    The parsed block:
        block name {
            content 1;
            content 2;
        }
    might be represented with the list [names, contents], where
        names = ["block", " ", "name", " "]
        contents = [["\n    ", "content", " ", "1"], ["\n    ", "content", " ", "2"], "\n"]
    """
    def __init__(self, context=None):
        super(Block, self).__init__(context)
        self.names = None # type: Sentence
        self.contents = None # type: Block

    @staticmethod
    def should_parse(lists):
        """ Returns True if `lists` can be parseable as a `Block`-- that is,
        it's got a length of 2, the first element is a `Sentence` and the second can be
        a `Directives`.

        :param list lists: The raw unparsed list to check.

        :returns: whether this lists is parseable by `Block`. """
        return isinstance(lists, list) and len(lists) == 2 and \
            Sentence.should_parse(lists[0]) and isinstance(lists[1], list)

    def iterate(self, expanded=False, match=None):
        """ Iterator over self, and if expanded is set, over its contents. """
        if match is None or match(self):
            yield self
        if expanded:
            for elem in self.contents.iterate(expanded, match):
                yield elem

    def parse(self, raw_list, add_spaces=False):
        """ Parses a list that resembles a block.

        The assumptions that this routine makes are:
            1. the first element of `raw_list` is a valid Sentence.
            2. the second element of `raw_list` is a valid Statement.
        If add_spaces is set, we call it recursively on `names` and `contents`, and
        add an extra trailing space to `names` (to separate the block's opening bracket
        and the block name).
        """
        if not Block.should_parse(raw_list):
            raise errors.MisconfigurationError("Block parsing expects a list of length 2. "
                "First element should be a list of string types (the bloc names), "
                "and second should be another list of directives (the bloc content).")
        self.names = Sentence(self.child_context())
        self.contents = Directives(self.child_context())
        self._data = [self.names, self.contents]
        if add_spaces:
            raw_list[0].append(" ")
        self.names.parse(raw_list[0], add_spaces)
        self.contents.parse(raw_list[1], add_spaces)

def _is_comment(parsed_obj):
    """ Checks whether parsed_obj is a comment.

    :param .Parsable parsed_obj:

    :returns: whether parsed_obj represents a comment sentence.
    :rtype bool:
    """
    if not isinstance(parsed_obj, Sentence):
        return False
    return parsed_obj.words[0] == "#"

def _is_certbot_comment(parsed_obj):
    """ Checks whether parsed_obj is a "managed by Certbot" comment.

    :param .Parsable parsed_obj:

    :returns: whether parsed_obj is a "managed by Certbot" comment.
    :rtype bool:
    """
    if not _is_comment(parsed_obj):
        return False
    if len(parsed_obj.words) != len(COMMENT_BLOCK):
        return False
    for i, word in enumerate(parsed_obj.words):
        if word != COMMENT_BLOCK[i]:
            return False
    return True

def _certbot_comment(context, preceding_spaces=4):
    """ A "Managed by Certbot" comment.
    :param int preceding_spaces: Number of spaces between the end of the previous
        statement and the comment.
    :returns: Sentence containing the comment.
    :rtype: .Sentence
    """
    result = Sentence(context)
    result.parse([" " * preceding_spaces] + COMMENT_BLOCK)
    return result

def _choose_parser(context, list_):
    """ Choose a parser from type(context).parsing_hooks, depending on whichever hook
    returns True first. """
    hooks = ParseContext.parsing_hooks()
    if context:
        hooks = type(context).parsing_hooks()
    for type_ in hooks:
        if type_.should_parse(list_):
            return type_(context)
    raise errors.MisconfigurationError(
        "None of the parsing hooks succeeded, so we don't know how to parse this set of lists.")

def parse_raw(lists_, context=None, add_spaces=False):
    """ Primary parsing factory function.

    :param list lists_: raw lists from pyparsing to parse.
    :param .ParseContext context: The context of this object.
    :param bool add_spaces: Whether to pass add_spaces to the parser.

    :returns .Parsable: The parsed object.

    :raises errors.MisconfigurationError: If no parsing hook passes, and we can't
        determine which type to parse the raw lists into.
    """
    if context is None:
        context = ParseContext()
    parser = _choose_parser(context, lists_)
    parser.parse(lists_, add_spaces)
    return parser

class ParseContext(object):
    """ Context information held by parsed objects.

    :param .Parsable parent: The parent object containing the associated object.
    :param str filename: relative file path that the associated object was parsed from
    :param str cwd: current working directory/root of the parsing files
    """

    __metaclass__ = abc.ABCMeta

    def __init__(self, parent=None, filename=None, cwd=None):
        self.parent = parent
        self.filename = filename
        self.cwd = cwd

    def child(self, parent, filename=None):
        """ Returns Context with all fields inherited, except parent points to this object.
        """
        return ParseContext(parent, filename if filename else self.filename, self.cwd)

    @staticmethod
    def parsing_hooks():
        """Returns object types that this class should be able to `parse` recusrively.
        The order of the objects indicates the order in which the parser should
        try to parse each subitem.
        :returns: A list of Parsable classes.
        :rtype list:
        """
        return (Block, Sentence, Directives)
