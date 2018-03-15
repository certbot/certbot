"""Very low-level dovecot config parser based on pyparsing."""
from pyparsing import (
    alphanums, restOfLine,
    Literal, Forward, Group, LineEnd, Optional,
    OneOrMore, ParserElement, White, Word, ZeroOrMore
)

class DovecotParser(object):
    # pylint: disable=expression-not-assigned
    """A class that parses dovecot configuration with pyparsing."""

    # pyparsing automatically uses whitespaces as delimeters for tokens.
    # Here, we're setting default whitespace characters to ` ` and `\t`,
    # excluding `\n` since a new line is used as a delimeter for dovecot
    # configuration itself
    ParserElement.setDefaultWhitespaceChars('')

    newline = LineEnd()
    same_line_space = Optional(Word(' \t').leaveWhitespace())
    space = Optional(White().leaveWhitespace())

    # Defining comments
    comment = Group(Literal('#') + restOfLine) + same_line_space

    # Defining key and value pair
    key = Word(alphanums) + same_line_space + (Literal('='))

    value_group = OneOrMore(
        same_line_space
        + Optional(Literal(',') + same_line_space)
        + Word(alphanums)
    )

    key_value_pair = (
        space + key + value_group + same_line_space
    )

    # Defining includes
    # Order matters. It's a first item match.
    include = (
        space
        + (Literal('!include_try') | Literal('!include'))
        + OneOrMore(same_line_space
        + Word(alphanums + "_/-?!"))
        + same_line_space
    )

    # Defining a block
    block = Forward()

    item = Group(comment | block | key_value_pair | include) + newline.suppress()

    block_title = Group(
        space + Word(alphanums) + same_line_space
        + Literal('{') + same_line_space + newline.suppress()
    )

    right_brace = Group(space + Literal('}') + same_line_space + Optional(comment))

    # The use of the OneOrMore(newline) here is actually not an assumption.
    # Dovecot requires every { to be followed by a new line, and every } to
    # be preceded and followed by a new line. Also, every key and value
    # pair have to be delimited by a new line.
    # Here a problem arises of picking whether { should always be followed
    # by a new line, or } should always be preceded by one. We are making
    # the choice to make sure all key value pairs in addition to { are
    # followed by a new line. This should maintain that  } is also always
    # preceded by a new line.
    block_body = (Group(
                        ZeroOrMore(item)
                  ) + right_brace)

    # Blocks contain of a list containing 3 lists. The first item is the
    # block name, while the second item is a list of the block contents,
    # and the third is the right brace and spaces surrounding it
    block << OneOrMore(block_title + block_body)

    result = ZeroOrMore(item) + space

    def parse_file(self, f):
        """Parses from a file.

        :param file f: The file to parse
        :returns: The parsed tree
        :rtype: list

        """
        handler = open(f, "r")
        text = handler.read()

        return self.parse_string(text)

    def parse_string(self, text):
        """Returns the parsed tree

        :param String text: The text to parse
        :returns: The parsed tree
        :rtype: list

        """

        return self.result.parseString(text)


class RawDovecotDumper(object):
    # pylint: disable=too-few-public-methods
    """A class that dumps dovecot configuration from the provided tree."""
    def __init__(self, tree):
        self.tree = tree

    def __iter__(self, tree=None):
        """Iterates the dumped dovecot content."""
        tree = tree or self.tree

        for item in tree:
            for i in self.parseItem(item):
                yield i

    def __str__(self):
        """Return the parsed block as a string."""
        return ''.join(self)

    def parseItem(self, item):
        """Parses a single item and yields line by line."""
        if len(item) == 2 and isinstance(item[1], list):
            # Block
            yield "".join(item[0]) + '{' + '\n'

            # Yield block contents
            for i in item[1]:
                for j in self.parseItem(i):
                    yield j

            yield '}' + '\n'
        elif isinstance(item, list):
            # Not a block
            yield "".join(item) + '\n'
        else:
            yield item
