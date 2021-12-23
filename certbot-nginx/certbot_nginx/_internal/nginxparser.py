"""Very low-level nginx config parser based on pyparsing."""
# Forked from https://github.com/fatiherikli/nginxparser (MIT Licensed)
import copy
import logging
from typing import Any
from typing import IO

from pyparsing import Combine
from pyparsing import Forward
from pyparsing import Group
from pyparsing import Literal
from pyparsing import Optional
from pyparsing import QuotedString
from pyparsing import Regex
from pyparsing import restOfLine
from pyparsing import stringEnd
from pyparsing import White
from pyparsing import ZeroOrMore

logger = logging.getLogger(__name__)


class RawNginxParser:
    # pylint: disable=pointless-statement
    """A class that parses nginx configuration with pyparsing."""

    # constants
    space = Optional(White()).leaveWhitespace()
    required_space = White().leaveWhitespace()

    left_bracket = Literal("{").suppress()
    right_bracket = space + Literal("}").suppress()
    semicolon = Literal(";").suppress()
    dquoted = QuotedString('"', multiline=True, unquoteResults=False, escChar='\\')
    squoted = QuotedString("'", multiline=True, unquoteResults=False, escChar='\\')
    quoted = dquoted | squoted
    head_tokenchars = Regex(r"(\$\{)|[^{};\s'\"]") # if (last_space)
    tail_tokenchars = Regex(r"(\$\{)|[^{;\s]") # else
    tokenchars = Combine(head_tokenchars + ZeroOrMore(tail_tokenchars))
    paren_quote_extend = Combine(quoted + Literal(')') + ZeroOrMore(tail_tokenchars))
    # note: ')' allows extension, but then we fall into else, not last_space.

    token = paren_quote_extend | tokenchars | quoted

    whitespace_token_group = space + token + ZeroOrMore(required_space + token) + space
    assignment = whitespace_token_group + semicolon

    comment = space + Literal('#') + restOfLine

    block = Forward()

    # order matters! see issue 518, and also http { # server { \n}
    contents = Group(comment) | Group(block) | Group(assignment)

    block_begin = Group(whitespace_token_group)
    block_innards = Group(ZeroOrMore(contents) + space).leaveWhitespace()
    block << block_begin + left_bracket + block_innards + right_bracket

    script = ZeroOrMore(contents) + space + stringEnd
    script.parseWithTabs().leaveWhitespace()

    def __init__(self, source):
        self.source = source

    def parse(self):
        """Returns the parsed tree."""
        return self.script.parseString(self.source)

    def as_list(self):
        """Returns the parsed tree as a list."""
        return self.parse().asList()

class RawNginxDumper:
    """A class that dumps nginx configuration from the provided tree."""
    def __init__(self, blocks):
        self.blocks = blocks

    def __iter__(self, blocks=None):
        """Iterates the dumped nginx content."""
        blocks = blocks or self.blocks
        for b0 in blocks:
            if isinstance(b0, str):
                yield b0
                continue
            item = copy.deepcopy(b0)
            if spacey(item[0]):
                yield item.pop(0) # indentation
                if not item:
                    continue

            if isinstance(item[0], list): # block
                yield "".join(item.pop(0)) + '{'
                for parameter in item.pop(0):
                    for line in self.__iter__([parameter]): # negate "for b0 in blocks"
                        yield line
                yield '}'
            else: # not a block - list of strings
                semicolon = ";"
                if isinstance(item[0], str) and item[0].strip() == '#': # comment
                    semicolon = ""
                yield "".join(item) + semicolon

    def __str__(self):
        """Return the parsed block as a string."""
        return ''.join(self)


spacey = lambda x: (isinstance(x, str) and x.isspace()) or x == ''


class UnspacedList(list):
    """Wrap a list [of lists], making any whitespace entries magically invisible"""

    def __init__(self, list_source):
        # ensure our argument is not a generator, and duplicate any sublists
        self.spaced = copy.deepcopy(list(list_source))
        self.dirty = False

        # Turn self into a version of the source list that has spaces removed
        # and all sub-lists also UnspacedList()ed
        list.__init__(self, list_source)
        for i, entry in reversed(list(enumerate(self))):
            if isinstance(entry, list):
                sublist = UnspacedList(entry)
                list.__setitem__(self, i, sublist)
                self.spaced[i] = sublist.spaced
            elif spacey(entry):
                # don't delete comments
                if "#" not in self[:i]:
                    list.__delitem__(self, i)

    def _coerce(self, inbound):
        """
        Coerce some inbound object to be appropriately usable in this object

        :param inbound: string or None or list or UnspacedList
        :returns: (coerced UnspacedList or string or None, spaced equivalent)
        :rtype: tuple

        """
        if not isinstance(inbound, list):                      # str or None
            return inbound, inbound
        else:
            if not hasattr(inbound, "spaced"):
                inbound = UnspacedList(inbound)
            return inbound, inbound.spaced

    def insert(self, i, x):
        """
        Inserts an item into the list at a given position.

        If the item is not spacey, it is inserted directly into the list. Otherwise, it is wrapped in a
        SpacedItem and inserted instead.
        """
        item, spaced_item = self._coerce(x)
        slicepos = self._spaced_position(i) if i < len(self) else len(self.spaced)
        self.spaced.insert(slicepos, spaced_item)
        if not spacey(item):
            list.insert(self, i, item)
        self.dirty = True

    def append(self, x):
        """
        Append an item to a SpacedList.

        :Parameters:
          - `x` (object): The object to append. If it is not a string, it will be converted into one by calling
        str(x).

          >>> from spacedlist import SpacedList
          >>> l = SpacedList() # Create an empty list with spacey=False and spaced=[]

          >>> l.append('a') #
        Append 'a' as-is, without adding spaces around it

          >>> print(l) # Print the result of appending 'a' to the list (without using print())
            ['a']
        >>> l.append('b') # Append 'b', which is converted into " b " by str() before being added to the list because spacey=False for this instance of
        SpacedList and no spaces were specified in between items when creating this instance of SpacedList with spaced=[]. This results in ['b'] being
        appended instead of [" b "] because there are no spaces specified between items in the constructor call for this instance of SpacedLIst so all items
        are simply concatenated together when they're added as-is without any spacing applied at all
        """
        item, spaced_item = self._coerce(x)
        self.spaced.append(spaced_item)
        if not spacey(item):
            list.append(self, item)
        self.dirty = True

    def extend(self, x):
        item, spaced_item = self._coerce(x)
        self.spaced.extend(spaced_item)
        list.extend(self, item)
        self.dirty = True

    def __add__(self, other):
        l = copy.deepcopy(self)
        l.extend(other)
        l.dirty = True
        return l

    def pop(self, _i=None):
        raise NotImplementedError("UnspacedList.pop() not yet implemented")
    def remove(self, _):
        raise NotImplementedError("UnspacedList.remove() not yet implemented")
    def reverse(self):
        raise NotImplementedError("UnspacedList.reverse() not yet implemented")
    def sort(self, _cmp=None, _key=None, _Rev=None):
        raise NotImplementedError("UnspacedList.sort() not yet implemented")
    def __setslice__(self, _i, _j, _newslice):
        raise NotImplementedError("Slice operations on UnspacedLists not yet implemented")

    def __setitem__(self, i, value):
        """
        __setitem__(i, value)
            If `i` is a slice, raise NotImplementedError. Otherwise, if the coerced value
            is not spacey (see below), set the
        corresponding list item to its coerced
            value. Then set the corresponding spaced item to its coerced value.

            Coercing `value` consists of two
        steps:

                1) If `value` has no __spaced__ method or any other discrepancy that would prevent it from being converted into a SpacedListItem
        instance, convert it into one by calling its __spacey__ method and converting this result into an equivalent SpacedListItem instance; see
        :meth:~spacy.parts_of_speech.SpacyPartOfSpeechBase._spacey for details on how this conversion works and what exactly gets converted into what (e.g.,
        strings are left alone while lists are recursively mapped using their first element).

                2) Convert whatever was produced in step 1 above back
        into a valid Python object that can be assigned as an index position in self's underlying list representation.
        """
        if isinstance(i, slice):
            raise NotImplementedError("Slice operations on UnspacedLists not yet implemented")
        item, spaced_item = self._coerce(value)
        self.spaced.__setitem__(self._spaced_position(i), spaced_item)
        if not spacey(item):
            list.__setitem__(self, i, item)
        self.dirty = True

    def __delitem__(self, i):
        self.spaced.__delitem__(self._spaced_position(i))
        list.__delitem__(self, i)
        self.dirty = True

    def __deepcopy__(self, memo):
        new_spaced = copy.deepcopy(self.spaced, memo=memo)
        l = UnspacedList(new_spaced)
        l.dirty = self.dirty
        return l

    def is_dirty(self):
        """Recurse through the parse tree to figure out if any sublists are dirty"""
        if self.dirty:
            return True
        return any((isinstance(x, UnspacedList) and x.is_dirty() for x in self))

    def _spaced_position(self, idx):
        "Convert from indexes in the unspaced list to positions in the spaced one"
        pos = spaces = 0
        # Normalize indexes like list[-1] etc, and save the result
        if idx < 0:
            idx = len(self) + idx
        if not 0 <= idx < len(self):
            raise IndexError("list index out of range")
        idx0 = idx
        # Count the number of spaces in the spaced list before idx in the unspaced one
        while idx != -1:
            if spacey(self.spaced[pos]):
                spaces += 1
            else:
                idx -= 1
            pos += 1
        return idx0 + spaces


# Shortcut functions to respect Python's serialization interface
# (like pyyaml, picker or json)

def loads(source):
    """Parses from a string.

    :param str source: The string to parse
    :returns: The parsed tree
    :rtype: list

    """
    return UnspacedList(RawNginxParser(source).as_list())


def load(_file):
    """Parses from a file.

    :param file _file: The file to parse
    :returns: The parsed tree
    :rtype: list

    """
    return loads(_file.read())


def dumps(blocks: UnspacedList) -> str:
    """Dump to a Unicode string.

    :param UnspacedList block: The parsed tree
    :rtype: six.text_type

    """
    return str(RawNginxDumper(blocks.spaced))


def dump(blocks: UnspacedList, _file: IO[Any]) -> None:
    """Dump to a file.

    :param UnspacedList block: The parsed tree
    :param IO[Any] _file: The file stream to dump to. It must be opened with
                          Unicode encoding.
    :rtype: None

    """
    _file.write(dumps(blocks))
