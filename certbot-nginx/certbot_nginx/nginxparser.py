"""Very low-level nginx config parser based on pyparsing."""
# Forked from https://github.com/fatiherikli/nginxparser (MIT Licensed)
import copy
import logging

from certbot.plugins.parse_common import spacey, UnspacedList

from pyparsing import (
    Literal, White, Forward, Group, Optional, OneOrMore, QuotedString, Regex, ZeroOrMore, Combine)
from pyparsing import stringEnd
from pyparsing import restOfLine
import six

logger = logging.getLogger(__name__)

class RawNginxParser(object):
    # pylint: disable=expression-not-assigned
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
    head_tokenchars = Regex(r"[^{};\s'\"]") # if (last_space)
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

    script = OneOrMore(contents) + space + stringEnd
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
            if isinstance(b0, six.string_types):
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
                if isinstance(item[0], six.string_types) and item[0].strip() == '#': # comment
                    semicolon = ""
                yield "".join(item) + semicolon

    def __str__(self):
        """Return the parsed block as a string."""
        return ''.join(self)


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
