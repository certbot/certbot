"""Very low-level nginx config parser based on pyparsing."""
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
    comment = Literal('#') + restOfLine()
    assignment = (key + Optional(space + value, default=None) + semicolon)
    location_statement = Optional(space + modifier) + Optional(space + location)
    if_statement = Literal("if") + space + Regex(r"\(.+\)") + space
    block = Forward()

    block << Group(
        (Group(key + location_statement) ^ Group(if_statement)) +
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
    return RawNginxParser(source).as_list()


def load(_file):
    """Parses from a file.

    :param file _file: The file to parse
    :returns: The parsed tree
    :rtype: list

    """
    return loads(_file.read())


def dumps(blocks, indentation=4):
    """Dump to a string.

    :param list block: The parsed tree
    :param int indentation: The number of spaces to indent
    :rtype: str

    """
    return str(RawNginxDumper(blocks, indentation))


def dump(blocks, _file, indentation=4):
    """Dump to a file.

    :param list block: The parsed tree
    :param file _file: The file to dump to
    :param int indentation: The number of spaces to indent
    :rtype: NoneType

    """
    return _file.write(dumps(blocks, indentation))
