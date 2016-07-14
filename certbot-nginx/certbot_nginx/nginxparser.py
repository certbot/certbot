"""Very low-level nginx config parser based on pyparsing."""
# Forked from https://github.com/fatiherikli/nginxparser (MIT Licensed)
import copy
import logging
import string

from pyparsing import (
    Literal, White, Word, alphanums, CharsNotIn, Combine, Forward, Group,
    Optional, OneOrMore, Regex, ZeroOrMore)
from pyparsing import stringEnd
from pyparsing import restOfLine

logger = logging.getLogger(__name__)

class RawNginxParser(object):
    # pylint: disable=expression-not-assigned
    """A class that parses nginx configuration with pyparsing."""

    # constants
    space = Optional(White())
    nonspace = Regex(r"\S+")
    left_bracket = Literal("{").suppress()
    right_bracket = space.leaveWhitespace() + Literal("}").suppress()
    semicolon = Literal(";").suppress()
    key = Word(alphanums + "_/+-.")
    dollar_var = Combine(Literal('$') + Regex(r"[^\{\};,\s]+"))
    condition = Regex(r"\(.+\)")
    # Matches anything that is not a special character AND any chars in single
    # or double quotes
    # All of these COULD be upgraded to something like
    # https://stackoverflow.com/a/16130746
    value = Regex(r"((\".*\")?(\'.*\')?[^\{\};,]?)+")
    location = CharsNotIn("{};," + string.whitespace)
    # modifier for location uri [ = | ~ | ~* | ^~ ]
    modifier = Literal("=") | Literal("~*") | Literal("~") | Literal("^~")

    # rules
    comment = space + Literal('#') + restOfLine()

    assignment = space + key + Optional(space + value, default=None) + semicolon
    location_statement = space + Optional(modifier) + Optional(space + location + space)
    if_statement = space + Literal("if") + space + condition + space
    charset_map_statement = space + Literal("charset_map") + space + value + space + value

    map_statement = space + Literal("map") + space + nonspace + space + dollar_var + space
    # This is NOT an accurate way to parse nginx map entries; it's almost
    # certianly too permissive and may be wrong in other ways, but it should
    # preserve things correctly in mmmmost or all cases.
    #
    #    - I can neither prove nor disprove that it is corect wrt all escaped
    #      semicolon situations
    # Addresses https://github.com/fatiherikli/nginxparser/issues/19
    map_pattern = Regex(r'".*"') | Regex(r"'.*'") | nonspace
    map_entry = space + map_pattern + space + value + space + semicolon
    map_block = Group(
        Group(map_statement).leaveWhitespace() +
        left_bracket +
        Group(ZeroOrMore(Group(comment | map_entry)) + space).leaveWhitespace() +
        right_bracket)

    block = Forward()

    # key could for instance be "server" or "http", or "location" (in which case
    # location_statement needs to have a non-empty location)

    block_begin = (Group(space + key + location_statement) ^ 
                   Group(if_statement) ^
                   Group(charset_map_statement)).leaveWhitespace()

    block_innards = Group(ZeroOrMore(Group(comment | assignment) | block | map_block) 
                          + space).leaveWhitespace()

    block << Group(block_begin + left_bracket + block_innards + right_bracket)

    script = OneOrMore(Group(comment | assignment) ^ block ^ map_block) + space + stringEnd
    script.parseWithTabs().leaveWhitespace()

    def __init__(self, source):
        self.source = source

    def parse(self):
        """Returns the parsed tree."""
        return self.script.parseString(self.source)

    def as_list(self):
        """Returns the parsed tree as a list."""
        return self.parse().asList()

class RawNginxDumper(object):
    # pylint: disable=too-few-public-methods
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
            b = copy.deepcopy(b0)
            if spacey(b[0]):
                yield b.pop(0) # indentation
                if not b:
                    continue
            key, values = b.pop(0), b.pop(0)

            if isinstance(key, list):
                yield "".join(key) + '{'
                for parameter in values:
                    for line in self.__iter__([parameter]): # negate "for b0 in blocks"
                        yield line
                yield '}'
            else:
                if isinstance(key, str) and key.strip() == '#':  # comment
                    yield key + values
                else:                                            # assignment
                    gap = ""
                    # Sometimes the parser has stuck some gap whitespace in here;
                    # if so rotate it into gap
                    if values and spacey(values):
                        gap = values
                        values = b.pop(0)
                    yield key + gap + values + ';'

    def __str__(self):
        """Return the parsed block as a string."""
        return ''.join(self)


# Shortcut functions to respect Python's serialization interface
# (like pyyaml, picker or json)

def loads(source):
    """Parses from a string.

    :param str souce: The string to parse
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


def dumps(blocks):
    """Dump to a string.

    :param UnspacedList block: The parsed tree
    :param int indentation: The number of spaces to indent
    :rtype: str

    """
    return str(RawNginxDumper(blocks.spaced))


def dump(blocks, _file):
    """Dump to a file.

    :param UnspacedList block: The parsed tree
    :param file _file: The file to dump to
    :param int indentation: The number of spaces to indent
    :rtype: NoneType

    """
    return _file.write(dumps(blocks))


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
            return (inbound, inbound)
        else:
            if not hasattr(inbound, "spaced"):
                inbound = UnspacedList(inbound)
            return (inbound, inbound.spaced)


    def insert(self, i, x):
        item, spaced_item = self._coerce(x)
        self.spaced.insert(self._spaced_position(i), spaced_item)
        list.insert(self, i, item)
        self.dirty = True

    def append(self, x):
        item, spaced_item = self._coerce(x)
        self.spaced.append(spaced_item)
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
        if isinstance(i, slice):
            raise NotImplementedError("Slice operations on UnspacedLists not yet implemented")
        item, spaced_item = self._coerce(value)
        self.spaced.__setitem__(self._spaced_position(i), spaced_item)
        list.__setitem__(self, i, item)
        self.dirty = True

    def __delitem__(self, i):
        self.spaced.__delitem__(self._spaced_position(i))
        list.__delitem__(self, i)
        self.dirty = True

    def __deepcopy__(self, memo):
        l = UnspacedList(self[:])
        l.spaced = copy.deepcopy(self.spaced, memo=memo)
        l.dirty = self.dirty
        return l

    def is_dirty(self):
        """Recurse through the parse tree to figure out if any sublists are dirty"""
        if self.dirty:
            return True
        return any((isinstance(x, list) and x.is_dirty() for x in self))

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
