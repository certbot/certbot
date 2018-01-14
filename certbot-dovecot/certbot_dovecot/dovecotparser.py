"""Very low-level dovecot config parser based on pyparsing."""

from pyparsing import (
    alphanums, restOfLine,
    Literal, Dict, Forward, Group, LineEnd, Optional,
    OneOrMore, ParserElement, Word, ZeroOrMore
)

class DovecotParser(object):
    # pylint: disable=expression-not-assigned
    """A class that parses dovecot configuration with pyparsing."""

    # pyparsing automatically uses whitespaces as delimeters for tokens.
    # Here, we're setting default whitespace characters to ` ` and `\t`,
    # excluding `\n` since a new line is used as a delimeter for dovecot
    # configuration itself
    ParserElement.setDefaultWhitespaceChars(' \t')

    newline = LineEnd().suppress()

    # Defining comments
    comment = Group(Literal('#') + restOfLine)
    comment_line = comment + OneOrMore(newline)

    # Defining key and value pair
    key = Word(alphanums) + (Literal('=').suppress())

    value_group = (OneOrMore(Optional(Literal(',')).suppress()
                   + Word(alphanums)) + Optional(comment))

    key_value_pair = Dict(Group(key + value_group)) + newline

    # Defining includes
    # Order matters. It's a first item match.
    include = Dict(Group(
        (Literal('!include_try') | Literal('!include'))
        + OneOrMore(Word(alphanums + "_/-?!")) + newline
    ))

    # Defining a block
    block = Forward()

    item = comment_line | block | key_value_pair | include

    block_title = Word(alphanums)

    left_brace = Literal('{').suppress() + Optional(comment)
    right_brace = Literal('}').suppress() + Optional(comment)

    # The use of the OneOrMore(newline) here is actually not an assumption.
    # Dovecot requires every { to be followed by a new line, and every } to
    # be preceded and followed by a new line. Also, every key and value
    # pair have to be delimited by a new line.
    # Here a problem arises of picking whether { should always be followed
    # by a new line, or } should always be preceded by one. We are making
    # the choice to make sure all key value pairs in addition to { are
    # followed by a new line. This should maintain that  } is also always
    # preceded by a new line.
    block_body = (left_brace + OneOrMore(newline)
                  + ZeroOrMore(item)
                  + ZeroOrMore(newline)
                  + right_brace + OneOrMore(newline))

    block << OneOrMore(Dict(Group(block_title + block_body)))

    result = ZeroOrMore(item)

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

# d = DovecotParser()
# print d.parse_file('file')['#']
