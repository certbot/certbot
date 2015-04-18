"""Very low-level nginx config parser based on pyparsing."""
import string

from pyparsing import (
    Literal, White, Word, alphanums, CharsNotIn, Forward, Group,
    Optional, OneOrMore, ZeroOrMore, pythonStyleComment)


class RawNginxParser(object):
    # pylint: disable=expression-not-assigned
    """
    A class that parses nginx configuration with pyparsing
    """

    # constants
    left_bracket = Literal("{").suppress()
    right_bracket = Literal("}").suppress()
    semicolon = Literal(";").suppress()
    space = White().suppress()
    key = Word(alphanums + "_/")
    value = CharsNotIn("{};,")
    location = CharsNotIn("{};," + string.whitespace)
    # modifier for location uri [ = | ~ | ~* | ^~ ]
    modifier = Literal("=") | Literal("~*") | Literal("~") | Literal("^~")

    # rules
    assignment = (key + Optional(space + value) + semicolon)
    block = Forward()

    block << Group(
        Group(key + Optional(space + modifier) + Optional(space + location))
        + left_bracket
        + Group(ZeroOrMore(Group(assignment) | block))
        + right_bracket)

    script = OneOrMore(Group(assignment) | block).ignore(pythonStyleComment)

    def __init__(self, source):
        self.source = source

    def parse(self):
        """
        Returns the parsed tree.
        """
        return self.script.parseString(self.source)

    def as_list(self):
        """
        Returns the list of tree.
        """
        return self.parse().asList()


class RawNginxDumper(object):
    # pylint: disable=too-few-public-methods
    """
    A class that dumps nginx configuration from the provided tree.
    """
    def __init__(self, blocks, indentation=4):
        self.blocks = blocks
        self.indentation = indentation

    def __iter__(self, blocks=None, current_indent=0, spacer=' '):
        """
        Iterates the dumped nginx content.
        """
        blocks = blocks or self.blocks
        for key, values in blocks:
            if current_indent:
                yield spacer
            indentation = spacer * current_indent
            if isinstance(key, list):
                yield indentation + spacer.join(key) + ' {'
                for parameter in values:
                    if isinstance(parameter[0], list):
                        dumped = self.__iter__(
                            [parameter],
                            current_indent + self.indentation)
                        for line in dumped:
                            yield line
                    else:
                        dumped = spacer.join(parameter) + ';'
                        yield spacer * (
                            current_indent + self.indentation) + dumped

                yield indentation + '}'
            else:
                yield spacer * current_indent + key + spacer + values + ';'

    def as_string(self):
        """
        Return the parsed block as a string.
        """
        return '\n'.join(self)


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
    return RawNginxDumper(blocks, indentation).as_string()


def dump(blocks, _file, indentation=4):
    """Dump to a file.

    :param list block: The parsed tree
    :param file _file: The file to dump to
    :param int indentation: The number of spaces to indent
    :rtype: NoneType

    """
    return _file.write(dumps(blocks, indentation))
