# type: ignore
# This module is not used for now, so we just skip type checking for the sake
# of simplicity.
""" This file contains parsing routines and object classes to help derive meaning from
raw lists of tokens from pyparsing. """

import abc
import logging
from typing import Any
from typing import Callable
from typing import Iterator
from typing import Optional
from typing import Sequence

from certbot import errors

logger = logging.getLogger(__name__)
COMMENT = " managed by Certbot"
COMMENT_BLOCK = ["#", COMMENT]


class Parsable:
    """ Abstract base class for "Parsable" objects whose underlying representation
    is a tree of lists.

    :param .Parsable parent: This object's parsed parent in the tree
    """

    __metaclass__ = abc.ABCMeta

    def __init__(self, parent: Optional["Parsable"] = None):
        self._data: list[Any] = []
        self._tabs = None
        self.parent = parent

    @classmethod
    def parsing_hooks(cls) -> tuple[type["Block"], type["Sentence"], type["Statements"]]:
        """Returns object types that this class should be able to `parse` recursively.
        The order of the objects indicates the order in which the parser should
        try to parse each subitem.
        :returns: A list of Parsable classes.
        :rtype list:
        """
        return Block, Sentence, Statements

    @staticmethod
    @abc.abstractmethod
    def should_parse(lists: Any) -> bool:
        """ Returns whether the contents of `lists` can be parsed into this object.

        :returns: Whether `lists` can be parsed as this object.
        :rtype bool:
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def parse(self, raw_list: list[Any], add_spaces: bool = False) -> None:
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
    def iterate(self, expanded: bool = False,
                match: Optional[Callable[["Parsable"], bool]] = None) -> Iterator[Any]:
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
    def get_tabs(self) -> str:
        """ Guess at the tabbing style of this parsed object, based on whitespace.

        If this object is a leaf, it deducts the tabbing based on its own contents.
        Other objects may guess by calling `get_tabs` recursively on child objects.

        :returns: Guess at tabbing for this object. Should only return whitespace strings
            that does not contain newlines.
        :rtype str:
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def set_tabs(self, tabs: str = "    ") -> None:
        """This tries to set and alter the tabbing of the current object to a desired
        whitespace string. Primarily meant for objects that were constructed, so they
        can conform to surrounding whitespace.

        :param str tabs: A whitespace string (not containing newlines).
        """
        raise NotImplementedError()

    def dump(self, include_spaces: bool = False) -> list[Any]:
        """ Dumps back to pyparsing-like list tree. The opposite of `parse`.

        Note: if this object has not been modified, `dump` with `include_spaces=True`
        should always return the original input of `parse`.

        :param bool include_spaces: If set to False, magically hides whitespace tokens from
            dumped output.

        :returns: Pyparsing-like list tree.
        :rtype list:
        """
        return [elem.dump(include_spaces) for elem in self._data]


class Statements(Parsable):
    """ A group or list of "Statements". A Statement is either a Block or a Sentence.

    The underlying representation is simply a list of these Statement objects, with
    an extra `_trailing_whitespace` string to keep track of the whitespace that does not
    precede any more statements.
    """
    def __init__(self, parent: Optional[Parsable] = None):
        super().__init__(parent)
        self._trailing_whitespace = None

    # ======== Begin overridden functions

    @staticmethod
    def should_parse(lists: Any) -> bool:
        return isinstance(lists, list)

    def set_tabs(self, tabs: str = "    ") -> None:
        """ Sets the tabbing for this set of statements. Does this by calling `set_tabs`
        on each of the child statements.

        Then, if a parent is present, sets trailing whitespace to parent tabbing. This
        is so that the trailing } of any Block that contains Statements lines up
        with parent tabbing.
        """
        for statement in self._data:
            statement.set_tabs(tabs)
        if self.parent is not None:
            self._trailing_whitespace = "\n" + self.parent.get_tabs()

    def parse(self, raw_list: list[Any], add_spaces: bool = False) -> None:
        """ Parses a list of statements.
        Expects all elements in `raw_list` to be parseable by `type(self).parsing_hooks`,
        with an optional whitespace string at the last index of `raw_list`.
        """
        if not isinstance(raw_list, list):
            raise errors.MisconfigurationError("Statements parsing expects a list!")
        # If there's a trailing whitespace in the list of statements, keep track of it.
        if raw_list and isinstance(raw_list[-1], str) and raw_list[-1].isspace():
            self._trailing_whitespace = raw_list[-1]
            raw_list = raw_list[:-1]
        self._data = [parse_raw(elem, self, add_spaces) for elem in raw_list]

    def get_tabs(self) -> str:
        """ Takes a guess at the tabbing of all contained Statements by retrieving the
        tabbing of the first Statement."""
        if self._data:
            return self._data[0].get_tabs()
        return ""

    def dump(self, include_spaces: bool = False) -> list[Any]:
        """ Dumps this object by first dumping each statement, then appending its
        trailing whitespace (if `include_spaces` is set) """
        data = super().dump(include_spaces)
        if include_spaces and self._trailing_whitespace is not None:
            return data + [self._trailing_whitespace]
        return data

    def iterate(self, expanded: bool = False,
                match: Optional[Callable[["Parsable"], bool]] = None) -> Iterator[Any]:
        """ Combines each statement's iterator.  """
        for elem in self._data:
            yield from elem.iterate(expanded, match)

    # ======== End overridden functions


def _space_list(list_: Sequence[Any]) -> list[str]:
    """ Inserts whitespace between adjacent non-whitespace tokens. """
    spaced_statement: list[str] = []
    for i in reversed(range(len(list_))):
        spaced_statement.insert(0, list_[i])
        if i > 0 and not list_[i].isspace() and not list_[i-1].isspace():
            spaced_statement.insert(0, " ")
    return spaced_statement


class Sentence(Parsable):
    """ A list of words. Non-whitespace words are typically separated with whitespace tokens. """

    # ======== Begin overridden functions

    @staticmethod
    def should_parse(lists: Any) -> bool:
        """ Returns True if `lists` can be parseable as a `Sentence`-- that is,
        every element is a string type.

        :param list lists: The raw unparsed list to check.

        :returns: whether this lists is parseable by `Sentence`.
        """
        return (isinstance(lists, list) and len(lists) > 0 and
                all(isinstance(elem, str) for elem in lists))

    def parse(self, raw_list: list[Any], add_spaces: bool = False) -> None:
        """ Parses a list of string types into this object.
        If add_spaces is set, adds whitespace tokens between adjacent non-whitespace tokens."""
        if add_spaces:
            raw_list = _space_list(raw_list)
        if (not isinstance(raw_list, list)
                or any(not isinstance(elem, str) for elem in raw_list)):
            raise errors.MisconfigurationError("Sentence parsing expects a list of string types.")
        self._data = raw_list

    def iterate(self, expanded: bool = False,
                match: Optional[Callable[[Parsable], bool]] = None) -> Iterator[Any]:
        """ Simply yields itself. """
        if match is None or match(self):
            yield self

    def set_tabs(self, tabs: str = "    ") -> None:
        """ Sets the tabbing on this sentence. Inserts a newline and `tabs` at the
        beginning of `self._data`. """
        if self._data[0].isspace():
            return
        self._data.insert(0, "\n" + tabs)

    def dump(self, include_spaces: bool = False) -> list[Any]:
        """ Dumps this sentence. If include_spaces is set, includes whitespace tokens."""
        if not include_spaces:
            return self.words
        return self._data

    def get_tabs(self) -> str:
        """ Guesses at the tabbing of this sentence. If the first element is whitespace,
        returns the whitespace after the rightmost newline in the string. """
        first = self._data[0]
        if not first.isspace():
            return ""
        rindex = first.rfind("\n")
        return first[rindex+1:]

    # ======== End overridden functions

    @property
    def words(self) -> list[str]:
        """ Iterates over words, but without spaces. Like Unspaced List. """
        return [word.strip("\"\'") for word in self._data if not word.isspace()]

    def __getitem__(self, index: int) -> str:
        return self.words[index]

    def __contains__(self, word: str) -> bool:
        return word in self.words


class Block(Parsable):
    """ Any sort of block, denoted by a block name and curly braces, like so:
    The parsed block:
        block name {
            content 1;
            content 2;
        }
    might be represented with the list [names, contents], where
        names = ["block", " ", "name", " "]
        contents = [["\n    ", "content", " ", "1"], ["\n    ", "content", " ", "2"], "\n"]
    """
    def __init__(self, parent: Optional[Parsable] = None) -> None:
        super().__init__(parent)
        self.names: Optional[Sentence] = None
        self.contents: Optional[Block] = None

    @staticmethod
    def should_parse(lists: Any) -> bool:
        """ Returns True if `lists` can be parseable as a `Block`-- that is,
        it's got a length of 2, the first element is a `Sentence` and the second can be
        a `Statements`.

        :param list lists: The raw unparsed list to check.

        :returns: whether this lists is parseable by `Block`. """
        return isinstance(lists, list) and len(lists) == 2 and \
               Sentence.should_parse(lists[0]) and isinstance(lists[1], list)

    def set_tabs(self, tabs: str = "    ") -> None:
        """ Sets tabs by setting equivalent tabbing on names, then adding tabbing
        to contents."""
        self.names.set_tabs(tabs)
        self.contents.set_tabs(tabs + "    ")

    def iterate(self, expanded: bool = False,
                match: Optional[Callable[[Parsable], bool]] = None) -> Iterator[Any]:
        """ Iterator over self, and if expanded is set, over its contents. """
        if match is None or match(self):
            yield self
        if expanded:
            yield from self.contents.iterate(expanded, match)

    def parse(self, raw_list: list[Any], add_spaces: bool = False) -> None:
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
                "First element should be a list of string types (the block names), "
                "and second should be another list of statements (the block content).")
        self.names = Sentence(self)
        if add_spaces:
            raw_list[0].append(" ")
        self.names.parse(raw_list[0], add_spaces)
        self.contents = Statements(self)
        self.contents.parse(raw_list[1], add_spaces)
        self._data = [self.names, self.contents]

    def get_tabs(self) -> str:
        """ Guesses tabbing by retrieving tabbing guess of self.names. """
        return self.names.get_tabs()


def _is_comment(parsed_obj: Parsable) -> bool:
    """ Checks whether parsed_obj is a comment.

    :param .Parsable parsed_obj:

    :returns: whether parsed_obj represents a comment sentence.
    :rtype bool:
    """
    if not isinstance(parsed_obj, Sentence):
        return False
    return parsed_obj.words[0] == "#"


def _is_certbot_comment(parsed_obj: Parsable) -> bool:
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


def _certbot_comment(parent: Parsable, preceding_spaces: int = 4) -> Sentence:
    """ A "Managed by Certbot" comment.
    :param int preceding_spaces: Number of spaces between the end of the previous
        statement and the comment.
    :returns: Sentence containing the comment.
    :rtype: .Sentence
    """
    result = Sentence(parent)
    result.parse([" " * preceding_spaces] + COMMENT_BLOCK)
    return result


def _choose_parser(parent: Parsable, list_: Any) -> Parsable:
    """ Choose a parser from type(parent).parsing_hooks, depending on whichever hook
    returns True first. """
    hooks = Parsable.parsing_hooks()
    if parent:
        hooks = type(parent).parsing_hooks()
    for type_ in hooks:
        if type_.should_parse(list_):
            return type_(parent)
    raise errors.MisconfigurationError(
        "None of the parsing hooks succeeded, so we don't know how to parse this set of lists.")


def parse_raw(lists_: Any, parent: Optional[Parsable] = None, add_spaces: bool = False) -> Parsable:
    """ Primary parsing factory function.

    :param list lists_: raw lists from pyparsing to parse.
    :param .Parent parent: The parent containing this object.
    :param bool add_spaces: Whether to pass add_spaces to the parser.

    :returns .Parsable: The parsed object.

    :raises errors.MisconfigurationError: If no parsing hook passes, and we can't
        determine which type to parse the raw lists into.
    """
    parser = _choose_parser(parent, lists_)
    parser.parse(lists_, add_spaces)
    return parser
