from __future__ import absolute_import


class TokenType(object):
    def __init__(self, name, contains_syntax=False):
        self.name = name
        self.contains_syntax = contains_syntax

    def __repr__(self):
        return '%s(%s)' % (self.__class__.__name__, self.name)


class TokenTypes(object):
    """
    Basically an enum, but Python 2 doesn't have enums in the standard library.
    """
    def __init__(self, names, contains_syntax):
        for name in names:
            setattr(self, name, TokenType(name, contains_syntax=name in contains_syntax))


PythonTokenTypes = TokenTypes((
    'STRING', 'NUMBER', 'NAME', 'ERRORTOKEN', 'NEWLINE', 'INDENT', 'DEDENT',
    'ERROR_DEDENT', 'FSTRING_STRING', 'FSTRING_START', 'FSTRING_END', 'OP',
    'ENDMARKER'),
    contains_syntax=('NAME', 'OP'),
)
