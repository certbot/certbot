"""Very low-level hand rolled nginx config parser, using recursive descent to
retain all parsed information, so that the file can be reconstituted."""

import StringIO

class ParseException(Exception):
    """A parsing exception happened."""
    def __init__(self, value):
        self.value = value
        super(ParseException, self).__init__()

    def __str__(self):
        return repr(self.value)

class RawNginxParser(object):
    # pylint: disable=expression-not-assigned
    """A class that parses nginx configuration."""

    def __init__(self, source):
        self.source = source

    def as_list(self):
        """Returns the parsed tree as a list."""
        return self.parse()

    def parse(self):
        """Returns the parsed tree."""
        return RawNginxParser.Internal(self.source).parse_file()

    class Internal(object):
        """An internal class to keep track of parsing state."""
        def __init__(self, source):
            self.src = StringIO.StringIO(source)
            self.peeked = None
            self.eof = False

        def _peek(self):
            if self.eof:
                return None

            if self.peeked is None:
                self.peeked = self.src.read(1)
                if self.peeked == '':
                    self.eof = True
                    return None
            return self.peeked

        def _read(self):
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

        def parse_file(self):
            """Tries to parse the file and returns a list of blocks parsed."""

            result = self._parse_block()
            if not self.eof:
                raise ParseException("Invalid configuration file")

            return result

        def _parse_block(self):
            result = []
            while True:
                res = self._parse_next()
                if res is None:
                    return result
                result.append(res)

        def _is_whitespace(self, val, includeNL):
            if includeNL:
                return val in [' ', '\t', '\n', '\r']
            return val in [' ', '\t']

        def _parse_whitespace(self, includeNL):
            if self._is_whitespace(self._peek(), includeNL):
                return self._read()
            return None

        def _is_at_newline(self):
            return self._peek() in ['\n', '\r']

        def _read_newline(self):
            if self._read() == '\r' and self._peek() == '\n':
                self._expect('\n')

        def _parse_newline(self):
            if self._is_at_newline():
                self._read_newline()
                return []
            return None

        def _collect_until_end_of_line(self):
            result = ''

            while not self._is_at_newline():
                result = result + self._read()

            self._read_newline()

            return result

        def _parse_comment(self):
            if self._peek() == '#':
                self._expect('#')
                return ['#', self._collect_until_end_of_line()]
            return None

        def _is_key_char(self, val):
            return val.isalnum() or val == '_' or val == '/'

        def _parse_key(self):
            result = ''
            while True:
                val = self._peek()
                if val is None or not self._is_key_char(val):
                    if result == '':
                        return None
                    return result
                result = result + self._read()

        def _parse_string(self):
            startVal = self._read()
            result = startVal
            while True:
                val = self._read()
                result = result + val
                if val == None:
                    raise ParseException("Invalid configuration file, unfinished string literal")
                if val == startVal:
                    return result

        def _parse_value(self):
            self._pass_whitespace(True)
            result = ''
            while True:
                val = self._peek()
                if val is None or val in ['{', ';']:
                    result = result.rstrip()
                    if result == '':
                        return None
                    return result
                if val == '"' or val == "'":
                    result = result + self._parse_string()
                else:
                    result = result + self._read()

        def _parse_modifier(self):
            """Parses a modifier - this is slightly looser than the original parser"""
            self._pass_whitespace(True)
            val = self._peek()
            if val in ['=', '~', '^']:
                first = self._read()
                second = self._peek()
                if not self._is_whitespace(second, True):
                    self._read()
                    return first + second
                else:
                    return first
            return None

        def _expect(self, val):
            """Reads a character, and raises an exception if it's not the expected value"""
            r = self._read()
            if r != val:
                raise ParseException("Expected %s but got %s" % (val, r))

        def _finish_assignment(self, directive, val):
            self._expect(';')
            directive.append(val)
            self._pass_whitespace(False)

            comment = self._parse_comment()
            if comment:
                directive.append(''.join(comment))
            else:
                self._parse_newline()
            return directive

        def _finish_block(self, directive, val):
            self._expect('{')
            self._parse_newline()
            block = self._parse_block()
            self._expect('}')
            self._parse_newline()
            if val:
                directive.append(val)
            return [directive, block]

        def _parse_assignment_or_block(self):
            key = self._parse_key()
            if key is None:
                return None
            result = [key]
            if key == 'location':
                mod = self._parse_modifier()
                if mod is not None:
                    result.append(mod)
            val = self._parse_value()
            nx = self._peek()

            if nx == ';':
                return self._finish_assignment(result, val)

            if nx == '{':
                return self._finish_block(result, val)

            raise ParseException("Bad configuration file - unfinished value")

        def _pass_whitespace(self, includeNL):
            while self._parse_whitespace(includeNL) is not None:
                pass

        def _parse_next(self):
            self._pass_whitespace(False)

            res = self._parse_newline()
            if res is not None:
                return res

            res = self._parse_comment()
            if res is not None:
                return res

            res = self._parse_assignment_or_block()
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
            key = block[0] if block else None
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
