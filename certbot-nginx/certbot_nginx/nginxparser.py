"""Very low-level nginx config parser based on pyparsing."""
import copy
import logging
import string

from pyparsing import (
    Literal, White, Word, alphanums, CharsNotIn, Forward, Group,
    Optional, OneOrMore, Regex, ZeroOrMore)
from pyparsing import stringEnd
from pyparsing import restOfLine

logger = logging.getLogger(__name__)

class RawNginxParser(object):
    # pylint: disable=expression-not-assigned
    """A class that parses nginx configuration with pyparsing."""

    # constants
    space = Optional(White())
    left_bracket = Literal("{").suppress()
    right_bracket = space.leaveWhitespace() + Literal("}").suppress()
    semicolon = Literal(";").suppress()
    key = Word(alphanums + "_/+-.")
    # Matches anything that is not a special character AND any chars in single
    # or double quotes
    value = Regex(r"((\".*\")?(\'.*\')?[^\{\};,]?)+")
    location = CharsNotIn("{};," + string.whitespace)
    # modifier for location uri [ = | ~ | ~* | ^~ ]
    modifier = Literal("=") | Literal("~*") | Literal("~") | Literal("^~")

    # rules
    comment = space + Literal('#') + restOfLine()

    assignment = space + key + Optional(space + value, default=None) + semicolon
    location_statement = space + Optional(modifier) + Optional(space + location + space)
    if_statement = space + Literal("if") + space + Regex(r"\(.+\)") + space
    map_statement = space + Literal("map") + space + Regex(r"\S+") + space + Regex(r"\$\S+") + space
    block = Forward()

    block << Group(
        # XXX could this "key" be Literal("location")?
        (Group(space + key + location_statement) ^ Group(if_statement) ^
        Group(map_statement)).leaveWhitespace() +
        left_bracket +
        Group(ZeroOrMore(Group(comment | assignment) | block) + space).leaveWhitespace() +
        right_bracket)

    script = OneOrMore(Group(comment | assignment) ^ block) + space + stringEnd
    script.parseWithTabs()

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
    def __init__(self, blocks, indentation=0):
        self.blocks = blocks
        self.indentation = indentation

    def __iter__(self, blocks=None):
        """Iterates the dumped nginx content."""
        blocks = blocks or self.blocks
        for b0 in blocks:
            if isinstance(b0, str):
                yield b0
                continue
            b = copy.deepcopy(b0)
            indentation = ""
            if spacey(b[0]):
                indentation = b.pop(0)
                if not b:
                    yield indentation
                    continue
            key = b.pop(0)
            values = b.pop(0)

            if isinstance(key, list):
                yield indentation + "".join(key) + '{'
                for parameter in values:
                    dumped = self.__iter__([parameter])
                    for line in dumped:
                        yield line
                yield '}'
            else:
                if isinstance(key, str) and key.strip() == '#':
                    yield indentation + key + values
                else:
                    gap = ""
                    # Sometimes the parser has stuck some gap whitespace in here;
                    # if so rotate it into gap
                    if values and spacey(values):
                        gap = values
                        values = b.pop(0)
                    #if values is None:
                    #    yield indentation + key + gap + ';'
                    #else:
                    #    yield indentation + key + gap + values + ';'
                    yield indentation + key + gap + values + ';'

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
        self.spaced = copy.deepcopy(list(list_source))

        # Turn self into a version of the source list that has spaces removed
        # and all sub-lists also UnspacedList()ed
        list.__init__(self, list_source)
        for i, entry in reversed(list(enumerate(self))):
            if isinstance(entry, list):
                sublist = UnspacedList(entry)
                list.__setitem__(self, i, sublist)
                self.spaced[i] = sublist.spaced
            elif spacey(entry):
                list.__delitem__(self, i)

    def insert(self, i, x):
        if hasattr(x, "spaced"):
            self.spaced.insert(i + self._spaces_before(i), x.spaced)
        else:
            self.spaced.insert(i + self._spaces_before(i), x)
        list.insert(self, i, x)

    def append(self, x):
        if hasattr(x, "spaced"):
            self.spaced.append(x.spaced)
        else:
            self.spaced.append(x)
        list.append(self, x)

    def extend(self, x):
        if hasattr(x, "spaced"):
            self.spaced.extend(x.spaced)
        else:
            self.spaced.extend(x)
            logger.debug("Weird, extending regular list %r to Unspaced %r", x, self)
        list.extend(self, x)

    def __add__(self, other):
        l = copy.deepcopy(self)
        l.extend(other)
        return l

    def __setitem__(self, i, value):
        if hasattr(value, "spaced"):
            self.spaced.__setitem__(i + self._spaces_before(i), value.spaced)
        else:
            self.spaced.__setitem__(i + self._spaces_before(i), value)
        list.__setitem__(self, i, value)

    def __delitem__(self, i):
        self.spaced.__delitem__(i + self._spaces_before(i))
        list.__delitem__(self, i)

    def __deepcopy__(self, memo):
        l = UnspacedList(self[:])
        l.spaced = copy.deepcopy(self.spaced)
        return l


    def _spaces_before(self, idx):
        "Count the number of spaces in the spaced list before pos idx in the spaceless one"
        spaces = 0
        pos = 0
        while idx != -1:
            if spacey(self.spaced[pos]):
                spaces += 1
            else:
                idx -= 1
            pos += 1
        return spaces
