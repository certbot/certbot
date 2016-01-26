"""Very low-level hand rolled nginx config parser, using recursive descent to
retain all parsed information, so that the file can be reconstituted."""

import StringIO
from letsencrypt import errors

class ParseException(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)

class RawNginxParser2(object):
    """A class that parses nginx configuration."""
    def __init__(self, source):
        self.source = source

    def as_list(self):
        return self.parse()

    def parse(self):
        """Returns the parsed tree."""
        return RawNginxParser2.InternalParser(self.source).parseFile()

    class InternalParser(object):
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


def loads(source):
    """Parses from a string.

    :param str souce: The string to parse
    :returns: The parsed tree
    :rtype: list

    """
    return RawNginxParser2(source).as_list()


def load(_file):
    """Parses from a file.

    :param file _file: The file to parse
    :returns: The parsed tree
    :rtype: list

    """
    return loads(_file.read())
