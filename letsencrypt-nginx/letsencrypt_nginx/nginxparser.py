"""Very low-level hand rolled nginx config parser, using recursive descent to
retain all parsed information, so that the file can be reconstituted."""

import StringIO

class ParseException(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)

class RawNginxParser(object):
    # pylint: disable=expression-not-assigned
    """A class that parses nginx configuration."""

    def __init__(self, source):
        self.source = source

    def as_list(self):
        return self.parse()

    def parse(self):
        """Returns the parsed tree."""
        return RawNginxParser.Internal(self.source).parseFile()

    class Internal(object):
        def __init__(self, source):
            self.src = StringIO.StringIO(source)
            self.peeked = None
            self.eof = False

        def peek(self):
            if self.eof:
                return None

            if self.peeked is None:
                self.peeked = self.src.read(1)
                if self.peeked == '':
                    self.eof = True
                    return None
            return self.peeked

        def read(self):
            if self.eof:
                return None

            if self.peeked:
                val = self.peeked
                self.peeked = None
                return val
            val = self.src.read(1)
            if val == '':
                self.eof = True
                return None
            return val

        def parseFile(self):
            result = self.parseBlock()
            if not(self.eof):
                raise ParseException("Invalid configuration file")

            return result

        def parseBlock(self):
            result = []
            while True:
                res = self.parseNext()
                if res is None:
                    return result
                result.append(res)

        def isWhitespace(self, val, includeNL):
            if includeNL:
                return val in [' ', '\t', '\n', '\r']
            else:
                return val in [' ', '\t']

        def parseWhitespace(self, includeNL):
            if self.isWhitespace(self.peek(), includeNL):
                return self.read()
            return None

        def isAtNewline(self):
            val = self.peek()
            return val == '\n' or val == '\r'

        def readNewline(self):
            if self.read() == '\r' and self.peek() == '\n':
                self.read()

        def parseNewline(self):
            if self.isAtNewline():
                self.readNewline()
                return []
            return None

        def readUntilEndOfLine(self):
            result = ''

            while not(self.isAtNewline()):
                result = result + self.read()

            self.readNewline()

            return result

        def parseComment(self):
            val = self.peek()
            if val == '#':
                self.read()
                return ['#', self.readUntilEndOfLine()]
            return None

        def isKeyChar(self, val):
            return val.isalnum() or val == '_' or val == '/'

        def parseKey(self):
            result = ''
            while True:
                val = self.peek()
                if val is None or not(self.isKeyChar(val)):
                    if result == '':
                        return None
                    return result
                result = result + self.read()

        def parseString(self):
            startVal = self.read()
            result = startVal
            while True:
                val = self.read()
                result = result + val
                if val == None:
                    raise ParseException("Invalid configuration file")
                if val == startVal:
                    return result

        def parseValue(self):
            self.passWhitespace(True)
            result = ''
            while True:
                val = self.peek()
                if val is None or val == '{' or val == '}' or val == ';':
                    result = result.rstrip()
                    if result == '':
                        return None
                    return result
                if val == '"' or val == "'":
                    result = result + self.parseString()
                else:
                    result = result + self.read()

        def parseModifier(self):
            """Parses a modifier - this is slightly looser than the original parser"""
            self.passWhitespace(True)
            val = self.peek()
            if val in ['=', '~', '^']:
                first = self.read()
                second = self.peek()
                if not(self.isWhitespace(second, True)):
                    self.read()
                    return first + second
                else:
                    return first
            return None

        def expect(self, val):
            r = self.read()
            if r != val:
                raise ParseException("Expected %s but got %s" % (val, r))

        def parseAssignmentOrBlock(self):
            key = self.parseKey()
            if key is None:
                return None
            result = [key]
            if key == 'location':
                mod = self.parseModifier()
                if mod is not None:
                    result.append(mod)
            val = self.parseValue()
            nx = self.peek()

            if nx == ';':
                self.expect(';')
                result.append(val)
                self.passWhitespace(False)
                comment = self.parseComment()
                if comment:
                    result.append(''.join(comment))
                    return result
                self.parseNewline()
                return result

            if nx == '{':
                self.expect('{')
                self.parseNewline()
                block = self.parseBlock()
                self.expect('}')
                self.parseNewline()
                if val:
                    result.append(val)
                return [result, block]


        def passWhitespace(self, includeNL):
            while self.parseWhitespace(includeNL) is not None:
                pass

        def parseNext(self):
            self.passWhitespace(False)

            res = self.parseNewline()
            if res is not None:
                return res

            res = self.parseComment()
            if res is not None:
                return res

            res = self.parseAssignmentOrBlock()
            if res is not None:
                return res

            return None

class RawNginxDumper(object):
    # pylint: disable=too-few-public-methods
    """A class that dumps nginx configuration from the provided tree."""
    def __init__(self, blocks, indentation=4):
        self.blocks = blocks
        self.indentation = indentation

    def __iter__(self, blocks=None, current_indent=0, spacer=' '):
        """Iterates the dumped nginx content."""
        blocks = blocks or self.blocks
        for block in blocks:
            key = block[0] if len(block) > 0 else None
            values = block[1] if len(block) > 1 else None
            comment = block[2] if len(block) > 2 else None

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
                if block == []:
                    yield ''
                elif key == '#':
                    yield spacer * current_indent + key + values
                else:
                    result = spacer * current_indent + key
                    if values is not None:
                        result = result + spacer + values
                    result = result + ';'
                    if comment is not None:
                        result = result + spacer + comment
                    yield result

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
