"""Very low-level nginx config parser based on pyparsing."""
import copy
import string

from pyparsing import (
    Literal, White, Word, alphanums, CharsNotIn, Forward, Group,
    Optional, OneOrMore, Regex, ZeroOrMore)
from pyparsing import stringEnd
from pyparsing import restOfLine


class RawNginxParser(object):
    # pylint: disable=expression-not-assigned
    """A class that parses nginx configuration with pyparsing."""

    # constants
    left_bracket = Literal("{").suppress()
    right_bracket = Literal("}").suppress()
    semicolon = Literal(";").suppress()
    space = White().suppress()
    key = Word(alphanums + "_/+-.")
    # Matches anything that is not a special character AND any chars in single
    # or double quotes
    value = Regex(r"((\".*\")?(\'.*\')?[^\{\};,]?)+")
    location = CharsNotIn("{};," + string.whitespace)
    # modifier for location uri [ = | ~ | ~* | ^~ ]
    modifier = Literal("=") | Literal("~*") | Literal("~") | Literal("^~")

    # rules
    comment = White() + Literal('#') + restOfLine()
    assignment = White() + key + Optional(space + value, default=None) + semicolon
    location_statement = Optional(space + modifier) + Optional(space + location)
    if_statement = Literal("if") + space + Regex(r"\(.+\)") + space
    map_statement = Literal("map") + space + Regex(r"\S+") + space + Regex(r"\$\S+") + space
    block = Forward()

    block << Group(
        (Group(key + location_statement) ^ Group(if_statement) ^ Group(map_statement)) +
        left_bracket +
        Group(ZeroOrMore(Group(comment | assignment) | block)) +
        right_bracket)

    script = OneOrMore(Group(comment | assignment) ^ block) + stringEnd

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

    def __iter__(self, blocks=None, current_indent=0, spacer=''):
        """Iterates the dumped nginx content."""
        blocks = blocks or self.blocks
        for key, values in blocks.spaced:
            #indentation = spacer * current_indent
            if isinstance(key, list):
                yield "".join(key) + ' {'

                for parameter in values:
                    dumped = self.__iter__([parameter], current_indent + self.indentation)
                    for line in dumped:
                        yield line

                yield '}'
            else:
                if key == '#':
                    yield key + values
                else:
                    if values is None:
                        yield key + ';'
                    else:
                        yield key + values + ';'

    def __str__(self):
        """Return the parsed block as a string."""
        return '\n'.join(self) + '\n'




class OldRawNginxDumper(object):
    # pylint: disable=too-few-public-methods
    """A class that dumps nginx configuration from the provided tree."""
    def __init__(self, blocks, indentation=4):
        self.blocks = blocks
        self.indentation = indentation

    def __iter__(self, blocks=None, current_indent=0, spacer=' '):
        """Iterates the dumped nginx content."""
        blocks = blocks or self.blocks
        for key, values in blocks:
            indentation = spacer * current_indent
            if isinstance(key, list):
                if current_indent:
                    yield ''
                yield indentation + spacer.join(key) + ' {'

                for parameter in values:
                    dumped = self.__iter__([parameter], current_indent + self.indentation)
                    for line in dumped:
                        yield line

                yield indentation + '}'
            else:
                if key == '#':
                    yield spacer * current_indent + key + values
                else:
                    if values is None:
                        yield spacer * current_indent + key + ';'
                    else:
                        yield spacer * current_indent + key + spacer + values + ';'

    def __str__(self):
        """Return the parsed block as a string."""
        return '\n'.join(self) + '\n'


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
    return UnspacedList(loads(_file.read()))


def dumps(blocks, indentation=4):
    """Dump to a string.

    :param UnspacedList block: The parsed tree
    :param int indentation: The number of spaces to indent
    :rtype: str

    """
    return str(RawNginxDumper(blocks, indentation))


def dump(blocks, _file, indentation=4):
    """Dump to a file.

    :param UnspacedList block: The parsed tree
    :param file _file: The file to dump to
    :param int indentation: The number of spaces to indent
    :rtype: NoneType

    """
    return _file.write(dumps(blocks, indentation))



spacey = lambda x: isinstance(x, str) and x.isspace()

class UnspacedList(list):
    """Wrap a list [of lists], making any whitespace entries magically invisible"""

    def __init__(self, list_source):
        self.spaced = copy.deepcopy(list(list_source))

        # Turn self into a version of the source list that has spaces removed
        # and all sub-lists also UnspacedList()ed
        list.__init__(self, list_source)
        for i, entry in reversed(list(enumerate(self))):
            if isinstance(entry, list):
                list.__setitem__(self, i, UnspacedList(entry))
            elif spacey(entry):
                list.__delitem__(self, i)

    def insert(self, i, x):
        self.spaced.insert(i + self._spaces_before(i), x)
        list.insert(self, i, x)

    def append(self, x):
        self.spaced.append(x)
        list.append(self, x)

    def extend(self, x):
        self.spaced.extend(x)
        list.extend(self, x)

    def __add__(self, other):
        if hasattr(other, "spaced"):
            # If the thing added to us is an UnspacedList, use its spaced form
            self.spaced.__add__(other.spaced)
        else:
            self.spaced.__add__(other)
        list.__add__(self, other)

    def __setitem__(self, i, value):
        self.spaced.__setitem__(i + self._spaces_before(i), value)
        list.__setitem__(self, i, value)

    def __delitem__(self, i):
        self.spaced.__delitem__(i + self._spaces_before(i))
        list.__delitem__(self, i)

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

    def with_spaces(self):
        return self.spaced

