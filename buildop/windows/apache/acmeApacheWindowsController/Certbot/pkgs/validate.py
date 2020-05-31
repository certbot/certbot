# validate.py
# A Validator object
# Copyright (C) 2005-2014:
# (name) : (email)
# Michael Foord: fuzzyman AT voidspace DOT org DOT uk
# Mark Andrews: mark AT la-la DOT com
# Nicola Larosa: nico AT tekNico DOT net
# Rob Dennis: rdennis AT gmail DOT com
# Eli Courtwright: eli AT courtwright DOT org

# This software is licensed under the terms of the BSD license.
# http://opensource.org/licenses/BSD-3-Clause

# ConfigObj 5 - main repository for documentation and issue tracking:
# https://github.com/DiffSK/configobj

"""
    The Validator object is used to check that supplied values 
    conform to a specification.
    
    The value can be supplied as a string - e.g. from a config file.
    In this case the check will also *convert* the value to
    the required type. This allows you to add validation
    as a transparent layer to access data stored as strings.
    The validation checks that the data is correct *and*
    converts it to the expected type.
    
    Some standard checks are provided for basic data types.
    Additional checks are easy to write. They can be
    provided when the ``Validator`` is instantiated or
    added afterwards.
    
    The standard functions work with the following basic data types :
    
    * integers
    * floats
    * booleans
    * strings
    * ip_addr
    
    plus lists of these datatypes
    
    Adding additional checks is done through coding simple functions.
    
    The full set of standard checks are : 
    
    * 'integer': matches integer values (including negative)
                 Takes optional 'min' and 'max' arguments : ::
    
                   integer()
                   integer(3, 9)  # any value from 3 to 9
                   integer(min=0) # any positive value
                   integer(max=9)
    
    * 'float': matches float values
               Has the same parameters as the integer check.
    
    * 'boolean': matches boolean values - ``True`` or ``False``
                 Acceptable string values for True are :
                   true, on, yes, 1
                 Acceptable string values for False are :
                   false, off, no, 0
    
                 Any other value raises an error.
    
    * 'ip_addr': matches an Internet Protocol address, v.4, represented
                 by a dotted-quad string, i.e. '1.2.3.4'.
    
    * 'string': matches any string.
                Takes optional keyword args 'min' and 'max'
                to specify min and max lengths of the string.
    
    * 'list': matches any list.
              Takes optional keyword args 'min', and 'max' to specify min and
              max sizes of the list. (Always returns a list.)
    
    * 'tuple': matches any tuple.
              Takes optional keyword args 'min', and 'max' to specify min and
              max sizes of the tuple. (Always returns a tuple.)
    
    * 'int_list': Matches a list of integers.
                  Takes the same arguments as list.
    
    * 'float_list': Matches a list of floats.
                    Takes the same arguments as list.
    
    * 'bool_list': Matches a list of boolean values.
                   Takes the same arguments as list.
    
    * 'ip_addr_list': Matches a list of IP addresses.
                     Takes the same arguments as list.
    
    * 'string_list': Matches a list of strings.
                     Takes the same arguments as list.
    
    * 'mixed_list': Matches a list with different types in 
                    specific positions. List size must match
                    the number of arguments.
    
                    Each position can be one of :
                    'integer', 'float', 'ip_addr', 'string', 'boolean'
    
                    So to specify a list with two strings followed
                    by two integers, you write the check as : ::
    
                      mixed_list('string', 'string', 'integer', 'integer')
    
    * 'pass': This check matches everything ! It never fails
              and the value is unchanged.
    
              It is also the default if no check is specified.
    
    * 'option': This check matches any from a list of options.
                You specify this check with : ::
    
                  option('option 1', 'option 2', 'option 3')
    
    You can supply a default value (returned if no value is supplied)
    using the default keyword argument.
    
    You specify a list argument for default using a list constructor syntax in
    the check : ::
    
        checkname(arg1, arg2, default=list('val 1', 'val 2', 'val 3'))
    
    A badly formatted set of arguments will raise a ``VdtParamError``.
"""

__version__ = '1.0.1'


__all__ = (
    '__version__',
    'dottedQuadToNum',
    'numToDottedQuad',
    'ValidateError',
    'VdtUnknownCheckError',
    'VdtParamError',
    'VdtTypeError',
    'VdtValueError',
    'VdtValueTooSmallError',
    'VdtValueTooBigError',
    'VdtValueTooShortError',
    'VdtValueTooLongError',
    'VdtMissingValue',
    'Validator',
    'is_integer',
    'is_float',
    'is_boolean',
    'is_list',
    'is_tuple',
    'is_ip_addr',
    'is_string',
    'is_int_list',
    'is_bool_list',
    'is_float_list',
    'is_string_list',
    'is_ip_addr_list',
    'is_mixed_list',
    'is_option',
    '__docformat__',
)


import re
import sys
from pprint import pprint

#TODO - #21 - six is part of the repo now, but we didn't switch over to it here
# this could be replaced if six is used for compatibility, or there are no
# more assertions about items being a string
if sys.version_info < (3,):
    string_type = basestring
else:
    string_type = str
    # so tests that care about unicode on 2.x can specify unicode, and the same
    # tests when run on 3.x won't complain about a undefined name "unicode"
    # since all strings are unicode on 3.x we just want to pass it through
    # unchanged
    unicode = lambda x: x
    # in python 3, all ints are equivalent to python 2 longs, and they'll
    # never show "L" in the repr
    long = int

_list_arg = re.compile(r'''
    (?:
        ([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*list\(
            (
                (?:
                    \s*
                    (?:
                        (?:".*?")|              # double quotes
                        (?:'.*?')|              # single quotes
                        (?:[^'",\s\)][^,\)]*?)  # unquoted
                    )
                    \s*,\s*
                )*
                (?:
                    (?:".*?")|              # double quotes
                    (?:'.*?')|              # single quotes
                    (?:[^'",\s\)][^,\)]*?)  # unquoted
                )?                          # last one
            )
        \)
    )
''', re.VERBOSE | re.DOTALL)    # two groups

_list_members = re.compile(r'''
    (
        (?:".*?")|              # double quotes
        (?:'.*?')|              # single quotes
        (?:[^'",\s=][^,=]*?)       # unquoted
    )
    (?:
    (?:\s*,\s*)|(?:\s*$)            # comma
    )
''', re.VERBOSE | re.DOTALL)    # one group

_paramstring = r'''
    (?:
        (
            (?:
                [a-zA-Z_][a-zA-Z0-9_]*\s*=\s*list\(
                    (?:
                        \s*
                        (?:
                            (?:".*?")|              # double quotes
                            (?:'.*?')|              # single quotes
                            (?:[^'",\s\)][^,\)]*?)       # unquoted
                        )
                        \s*,\s*
                    )*
                    (?:
                        (?:".*?")|              # double quotes
                        (?:'.*?')|              # single quotes
                        (?:[^'",\s\)][^,\)]*?)       # unquoted
                    )?                              # last one
                \)
            )|
            (?:
                (?:".*?")|              # double quotes
                (?:'.*?')|              # single quotes
                (?:[^'",\s=][^,=]*?)|       # unquoted
                (?:                         # keyword argument
                    [a-zA-Z_][a-zA-Z0-9_]*\s*=\s*
                    (?:
                        (?:".*?")|              # double quotes
                        (?:'.*?')|              # single quotes
                        (?:[^'",\s=][^,=]*?)       # unquoted
                    )
                )
            )
        )
        (?:
            (?:\s*,\s*)|(?:\s*$)            # comma
        )
    )
    '''

_matchstring = '^%s*' % _paramstring

# Python pre 2.2.1 doesn't have bool
try:
    bool
except NameError:
    def bool(val):
        """Simple boolean equivalent function. """
        if val:
            return 1
        else:
            return 0


def dottedQuadToNum(ip):
    """
    Convert decimal dotted quad string to long integer
    
    >>> int(dottedQuadToNum('1 '))
    1
    >>> int(dottedQuadToNum(' 1.2'))
    16777218
    >>> int(dottedQuadToNum(' 1.2.3 '))
    16908291
    >>> int(dottedQuadToNum('1.2.3.4'))
    16909060
    >>> dottedQuadToNum('255.255.255.255')
    4294967295
    >>> dottedQuadToNum('255.255.255.256')
    Traceback (most recent call last):
    ValueError: Not a good dotted-quad IP: 255.255.255.256
    """
    
    # import here to avoid it when ip_addr values are not used
    import socket, struct
    
    try:
        return struct.unpack('!L',
            socket.inet_aton(ip.strip()))[0]
    except socket.error:
        raise ValueError('Not a good dotted-quad IP: %s' % ip)
    return


def numToDottedQuad(num):
    """
    Convert int or long int to dotted quad string
    
    >>> numToDottedQuad(long(-1))
    Traceback (most recent call last):
    ValueError: Not a good numeric IP: -1
    >>> numToDottedQuad(long(1))
    '0.0.0.1'
    >>> numToDottedQuad(long(16777218))
    '1.0.0.2'
    >>> numToDottedQuad(long(16908291))
    '1.2.0.3'
    >>> numToDottedQuad(long(16909060))
    '1.2.3.4'
    >>> numToDottedQuad(long(4294967295))
    '255.255.255.255'
    >>> numToDottedQuad(long(4294967296))
    Traceback (most recent call last):
    ValueError: Not a good numeric IP: 4294967296
    >>> numToDottedQuad(-1)
    Traceback (most recent call last):
    ValueError: Not a good numeric IP: -1
    >>> numToDottedQuad(1)
    '0.0.0.1'
    >>> numToDottedQuad(16777218)
    '1.0.0.2'
    >>> numToDottedQuad(16908291)
    '1.2.0.3'
    >>> numToDottedQuad(16909060)
    '1.2.3.4'
    >>> numToDottedQuad(4294967295)
    '255.255.255.255'
    >>> numToDottedQuad(4294967296)
    Traceback (most recent call last):
    ValueError: Not a good numeric IP: 4294967296

    """
    
    # import here to avoid it when ip_addr values are not used
    import socket, struct
    
    # no need to intercept here, 4294967295L is fine
    if num > long(4294967295) or num < 0:
        raise ValueError('Not a good numeric IP: %s' % num)
    try:
        return socket.inet_ntoa(
            struct.pack('!L', long(num)))
    except (socket.error, struct.error, OverflowError):
        raise ValueError('Not a good numeric IP: %s' % num)


class ValidateError(Exception):
    """
    This error indicates that the check failed.
    It can be the base class for more specific errors.
    
    Any check function that fails ought to raise this error.
    (or a subclass)
    
    >>> raise ValidateError
    Traceback (most recent call last):
    ValidateError
    """


class VdtMissingValue(ValidateError):
    """No value was supplied to a check that needed one."""


class VdtUnknownCheckError(ValidateError):
    """An unknown check function was requested"""

    def __init__(self, value):
        """
        >>> raise VdtUnknownCheckError('yoda')
        Traceback (most recent call last):
        VdtUnknownCheckError: the check "yoda" is unknown.
        """
        ValidateError.__init__(self, 'the check "%s" is unknown.' % (value,))


class VdtParamError(SyntaxError):
    """An incorrect parameter was passed"""

    def __init__(self, name, value):
        """
        >>> raise VdtParamError('yoda', 'jedi')
        Traceback (most recent call last):
        VdtParamError: passed an incorrect value "jedi" for parameter "yoda".
        """
        SyntaxError.__init__(self, 'passed an incorrect value "%s" for parameter "%s".' % (value, name))


class VdtTypeError(ValidateError):
    """The value supplied was of the wrong type"""

    def __init__(self, value):
        """
        >>> raise VdtTypeError('jedi')
        Traceback (most recent call last):
        VdtTypeError: the value "jedi" is of the wrong type.
        """
        ValidateError.__init__(self, 'the value "%s" is of the wrong type.' % (value,))


class VdtValueError(ValidateError):
    """The value supplied was of the correct type, but was not an allowed value."""
    
    def __init__(self, value):
        """
        >>> raise VdtValueError('jedi')
        Traceback (most recent call last):
        VdtValueError: the value "jedi" is unacceptable.
        """
        ValidateError.__init__(self, 'the value "%s" is unacceptable.' % (value,))


class VdtValueTooSmallError(VdtValueError):
    """The value supplied was of the correct type, but was too small."""

    def __init__(self, value):
        """
        >>> raise VdtValueTooSmallError('0')
        Traceback (most recent call last):
        VdtValueTooSmallError: the value "0" is too small.
        """
        ValidateError.__init__(self, 'the value "%s" is too small.' % (value,))


class VdtValueTooBigError(VdtValueError):
    """The value supplied was of the correct type, but was too big."""

    def __init__(self, value):
        """
        >>> raise VdtValueTooBigError('1')
        Traceback (most recent call last):
        VdtValueTooBigError: the value "1" is too big.
        """
        ValidateError.__init__(self, 'the value "%s" is too big.' % (value,))


class VdtValueTooShortError(VdtValueError):
    """The value supplied was of the correct type, but was too short."""

    def __init__(self, value):
        """
        >>> raise VdtValueTooShortError('jed')
        Traceback (most recent call last):
        VdtValueTooShortError: the value "jed" is too short.
        """
        ValidateError.__init__(
            self,
            'the value "%s" is too short.' % (value,))


class VdtValueTooLongError(VdtValueError):
    """The value supplied was of the correct type, but was too long."""

    def __init__(self, value):
        """
        >>> raise VdtValueTooLongError('jedie')
        Traceback (most recent call last):
        VdtValueTooLongError: the value "jedie" is too long.
        """
        ValidateError.__init__(self, 'the value "%s" is too long.' % (value,))


class Validator(object):
    """
    Validator is an object that allows you to register a set of 'checks'.
    These checks take input and test that it conforms to the check.
    
    This can also involve converting the value from a string into
    the correct datatype.
    
    The ``check`` method takes an input string which configures which
    check is to be used and applies that check to a supplied value.
    
    An example input string would be:
    'int_range(param1, param2)'
    
    You would then provide something like:
    
    >>> def int_range_check(value, min, max):
    ...     # turn min and max from strings to integers
    ...     min = int(min)
    ...     max = int(max)
    ...     # check that value is of the correct type.
    ...     # possible valid inputs are integers or strings
    ...     # that represent integers
    ...     if not isinstance(value, (int, long, string_type)):
    ...         raise VdtTypeError(value)
    ...     elif isinstance(value, string_type):
    ...         # if we are given a string
    ...         # attempt to convert to an integer
    ...         try:
    ...             value = int(value)
    ...         except ValueError:
    ...             raise VdtValueError(value)
    ...     # check the value is between our constraints
    ...     if not min <= value:
    ...          raise VdtValueTooSmallError(value)
    ...     if not value <= max:
    ...          raise VdtValueTooBigError(value)
    ...     return value
    
    >>> fdict = {'int_range': int_range_check}
    >>> vtr1 = Validator(fdict)
    >>> vtr1.check('int_range(20, 40)', '30')
    30
    >>> vtr1.check('int_range(20, 40)', '60')
    Traceback (most recent call last):
    VdtValueTooBigError: the value "60" is too big.
    
    New functions can be added with : ::
    
    >>> vtr2 = Validator()       
    >>> vtr2.functions['int_range'] = int_range_check
    
    Or by passing in a dictionary of functions when Validator 
    is instantiated.
    
    Your functions *can* use keyword arguments,
    but the first argument should always be 'value'.
    
    If the function doesn't take additional arguments,
    the parentheses are optional in the check.
    It can be written with either of : ::
    
        keyword = function_name
        keyword = function_name()
    
    The first program to utilise Validator() was Michael Foord's
    ConfigObj, an alternative to ConfigParser which supports lists and
    can validate a config file using a config schema.
    For more details on using Validator with ConfigObj see:
    https://configobj.readthedocs.org/en/latest/configobj.html
    """

    # this regex does the initial parsing of the checks
    _func_re = re.compile(r'(.+?)\((.*)\)', re.DOTALL)

    # this regex takes apart keyword arguments
    _key_arg = re.compile(r'^([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*(.*)$',  re.DOTALL)


    # this regex finds keyword=list(....) type values
    _list_arg = _list_arg

    # this regex takes individual values out of lists - in one pass
    _list_members = _list_members

    # These regexes check a set of arguments for validity
    # and then pull the members out
    _paramfinder = re.compile(_paramstring, re.VERBOSE | re.DOTALL)
    _matchfinder = re.compile(_matchstring, re.VERBOSE | re.DOTALL)


    def __init__(self, functions=None):
        """
        >>> vtri = Validator()
        """
        self.functions = {
            '': self._pass,
            'integer': is_integer,
            'float': is_float,
            'boolean': is_boolean,
            'ip_addr': is_ip_addr,
            'string': is_string,
            'list': is_list,
            'tuple': is_tuple,
            'int_list': is_int_list,
            'float_list': is_float_list,
            'bool_list': is_bool_list,
            'ip_addr_list': is_ip_addr_list,
            'string_list': is_string_list,
            'mixed_list': is_mixed_list,
            'pass': self._pass,
            'option': is_option,
            'force_list': force_list,
        }
        if functions is not None:
            self.functions.update(functions)
        # tekNico: for use by ConfigObj
        self.baseErrorClass = ValidateError
        self._cache = {}


    def check(self, check, value, missing=False):
        """
        Usage: check(check, value)
        
        Arguments:
            check: string representing check to apply (including arguments)
            value: object to be checked
        Returns value, converted to correct type if necessary
        
        If the check fails, raises a ``ValidateError`` subclass.
        
        >>> vtor.check('yoda', '')
        Traceback (most recent call last):
        VdtUnknownCheckError: the check "yoda" is unknown.
        >>> vtor.check('yoda()', '')
        Traceback (most recent call last):
        VdtUnknownCheckError: the check "yoda" is unknown.
        
        >>> vtor.check('string(default="")', '', missing=True)
        ''
        """
        fun_name, fun_args, fun_kwargs, default = self._parse_with_caching(check)
            
        if missing:
            if default is None:
                # no information needed here - to be handled by caller
                raise VdtMissingValue()
            value = self._handle_none(default)
        
        if value is None:
            return None
        
        return self._check_value(value, fun_name, fun_args, fun_kwargs)


    def _handle_none(self, value):
        if value == 'None':
            return None
        elif value in ("'None'", '"None"'):
            # Special case a quoted None
            value = self._unquote(value)
        return value


    def _parse_with_caching(self, check):
        if check in self._cache:
            fun_name, fun_args, fun_kwargs, default = self._cache[check]
            # We call list and dict below to work with *copies* of the data
            # rather than the original (which are mutable of course)
            fun_args = list(fun_args)
            fun_kwargs = dict(fun_kwargs)
        else:
            fun_name, fun_args, fun_kwargs, default = self._parse_check(check)
            fun_kwargs = dict([(str(key), value) for (key, value) in list(fun_kwargs.items())])
            self._cache[check] = fun_name, list(fun_args), dict(fun_kwargs), default
        return fun_name, fun_args, fun_kwargs, default
        
        
    def _check_value(self, value, fun_name, fun_args, fun_kwargs):
        try:
            fun = self.functions[fun_name]
        except KeyError:
            raise VdtUnknownCheckError(fun_name)
        else:
            return fun(value, *fun_args, **fun_kwargs)


    def _parse_check(self, check):
        fun_match = self._func_re.match(check)
        if fun_match:
            fun_name = fun_match.group(1)
            arg_string = fun_match.group(2)
            arg_match = self._matchfinder.match(arg_string)
            if arg_match is None:
                # Bad syntax
                raise VdtParamError('Bad syntax in check "%s".' % check)
            fun_args = []
            fun_kwargs = {}
            # pull out args of group 2
            for arg in self._paramfinder.findall(arg_string):
                # args may need whitespace removing (before removing quotes)
                arg = arg.strip()
                listmatch = self._list_arg.match(arg)
                if listmatch:
                    key, val = self._list_handle(listmatch)
                    fun_kwargs[key] = val
                    continue
                keymatch = self._key_arg.match(arg)
                if keymatch:
                    val = keymatch.group(2)
                    if not val in ("'None'", '"None"'):
                        # Special case a quoted None
                        val = self._unquote(val)
                    fun_kwargs[keymatch.group(1)] = val
                    continue
                
                fun_args.append(self._unquote(arg))
        else:
            # allows for function names without (args)
            return check, (), {}, None

        # Default must be deleted if the value is specified too,
        # otherwise the check function will get a spurious "default" keyword arg
        default = fun_kwargs.pop('default', None)
        return fun_name, fun_args, fun_kwargs, default


    def _unquote(self, val):
        """Unquote a value if necessary."""
        if (len(val) >= 2) and (val[0] in ("'", '"')) and (val[0] == val[-1]):
            val = val[1:-1]
        return val


    def _list_handle(self, listmatch):
        """Take apart a ``keyword=list('val, 'val')`` type string."""
        out = []
        name = listmatch.group(1)
        args = listmatch.group(2)
        for arg in self._list_members.findall(args):
            out.append(self._unquote(arg))
        return name, out


    def _pass(self, value):
        """
        Dummy check that always passes
        
        >>> vtor.check('', 0)
        0
        >>> vtor.check('', '0')
        '0'
        """
        return value
    
    
    def get_default_value(self, check):
        """
        Given a check, return the default value for the check
        (converted to the right type).
        
        If the check doesn't specify a default value then a
        ``KeyError`` will be raised.
        """
        fun_name, fun_args, fun_kwargs, default = self._parse_with_caching(check)
        if default is None:
            raise KeyError('Check "%s" has no default value.' % check)
        value = self._handle_none(default)
        if value is None:
            return value
        return self._check_value(value, fun_name, fun_args, fun_kwargs)


def _is_num_param(names, values, to_float=False):
    """
    Return numbers from inputs or raise VdtParamError.
    
    Lets ``None`` pass through.
    Pass in keyword argument ``to_float=True`` to
    use float for the conversion rather than int.
    
    >>> _is_num_param(('', ''), (0, 1.0))
    [0, 1]
    >>> _is_num_param(('', ''), (0, 1.0), to_float=True)
    [0.0, 1.0]
    >>> _is_num_param(('a'), ('a'))
    Traceback (most recent call last):
    VdtParamError: passed an incorrect value "a" for parameter "a".
    """
    fun = to_float and float or int
    out_params = []
    for (name, val) in zip(names, values):
        if val is None:
            out_params.append(val)
        elif isinstance(val, (int, long, float, string_type)):
            try:
                out_params.append(fun(val))
            except ValueError as e:
                raise VdtParamError(name, val)
        else:
            raise VdtParamError(name, val)
    return out_params


# built in checks
# you can override these by setting the appropriate name
# in Validator.functions
# note: if the params are specified wrongly in your input string,
#       you will also raise errors.

def is_integer(value, min=None, max=None):
    """
    A check that tests that a given value is an integer (int, or long)
    and optionally, between bounds. A negative value is accepted, while
    a float will fail.
    
    If the value is a string, then the conversion is done - if possible.
    Otherwise a VdtError is raised.
    
    >>> vtor.check('integer', '-1')
    -1
    >>> vtor.check('integer', '0')
    0
    >>> vtor.check('integer', 9)
    9
    >>> vtor.check('integer', 'a')
    Traceback (most recent call last):
    VdtTypeError: the value "a" is of the wrong type.
    >>> vtor.check('integer', '2.2')
    Traceback (most recent call last):
    VdtTypeError: the value "2.2" is of the wrong type.
    >>> vtor.check('integer(10)', '20')
    20
    >>> vtor.check('integer(max=20)', '15')
    15
    >>> vtor.check('integer(10)', '9')
    Traceback (most recent call last):
    VdtValueTooSmallError: the value "9" is too small.
    >>> vtor.check('integer(10)', 9)
    Traceback (most recent call last):
    VdtValueTooSmallError: the value "9" is too small.
    >>> vtor.check('integer(max=20)', '35')
    Traceback (most recent call last):
    VdtValueTooBigError: the value "35" is too big.
    >>> vtor.check('integer(max=20)', 35)
    Traceback (most recent call last):
    VdtValueTooBigError: the value "35" is too big.
    >>> vtor.check('integer(0, 9)', False)
    0
    """
    (min_val, max_val) = _is_num_param(('min', 'max'), (min, max))
    if not isinstance(value, (int, long, string_type)):
        raise VdtTypeError(value)
    if isinstance(value, string_type):
        # if it's a string - does it represent an integer ?
        try:
            value = int(value)
        except ValueError:
            raise VdtTypeError(value)
    if (min_val is not None) and (value < min_val):
        raise VdtValueTooSmallError(value)
    if (max_val is not None) and (value > max_val):
        raise VdtValueTooBigError(value)
    return value


def is_float(value, min=None, max=None):
    """
    A check that tests that a given value is a float
    (an integer will be accepted), and optionally - that it is between bounds.
    
    If the value is a string, then the conversion is done - if possible.
    Otherwise a VdtError is raised.
    
    This can accept negative values.
    
    >>> vtor.check('float', '2')
    2.0
    
    From now on we multiply the value to avoid comparing decimals
    
    >>> vtor.check('float', '-6.8') * 10
    -68.0
    >>> vtor.check('float', '12.2') * 10
    122.0
    >>> vtor.check('float', 8.4) * 10
    84.0
    >>> vtor.check('float', 'a')
    Traceback (most recent call last):
    VdtTypeError: the value "a" is of the wrong type.
    >>> vtor.check('float(10.1)', '10.2') * 10
    102.0
    >>> vtor.check('float(max=20.2)', '15.1') * 10
    151.0
    >>> vtor.check('float(10.0)', '9.0')
    Traceback (most recent call last):
    VdtValueTooSmallError: the value "9.0" is too small.
    >>> vtor.check('float(max=20.0)', '35.0')
    Traceback (most recent call last):
    VdtValueTooBigError: the value "35.0" is too big.
    """
    (min_val, max_val) = _is_num_param(
        ('min', 'max'), (min, max), to_float=True)
    if not isinstance(value, (int, long, float, string_type)):
        raise VdtTypeError(value)
    if not isinstance(value, float):
        # if it's a string - does it represent a float ?
        try:
            value = float(value)
        except ValueError:
            raise VdtTypeError(value)
    if (min_val is not None) and (value < min_val):
        raise VdtValueTooSmallError(value)
    if (max_val is not None) and (value > max_val):
        raise VdtValueTooBigError(value)
    return value


bool_dict = {
    True: True, 'on': True, '1': True, 'true': True, 'yes': True, 
    False: False, 'off': False, '0': False, 'false': False, 'no': False,
}


def is_boolean(value):
    """
    Check if the value represents a boolean.
    
    >>> vtor.check('boolean', 0)
    0
    >>> vtor.check('boolean', False)
    0
    >>> vtor.check('boolean', '0')
    0
    >>> vtor.check('boolean', 'off')
    0
    >>> vtor.check('boolean', 'false')
    0
    >>> vtor.check('boolean', 'no')
    0
    >>> vtor.check('boolean', 'nO')
    0
    >>> vtor.check('boolean', 'NO')
    0
    >>> vtor.check('boolean', 1)
    1
    >>> vtor.check('boolean', True)
    1
    >>> vtor.check('boolean', '1')
    1
    >>> vtor.check('boolean', 'on')
    1
    >>> vtor.check('boolean', 'true')
    1
    >>> vtor.check('boolean', 'yes')
    1
    >>> vtor.check('boolean', 'Yes')
    1
    >>> vtor.check('boolean', 'YES')
    1
    >>> vtor.check('boolean', '')
    Traceback (most recent call last):
    VdtTypeError: the value "" is of the wrong type.
    >>> vtor.check('boolean', 'up')
    Traceback (most recent call last):
    VdtTypeError: the value "up" is of the wrong type.
    
    """
    if isinstance(value, string_type):
        try:
            return bool_dict[value.lower()]
        except KeyError:
            raise VdtTypeError(value)
    # we do an equality test rather than an identity test
    # this ensures Python 2.2 compatibilty
    # and allows 0 and 1 to represent True and False
    if value == False:
        return False
    elif value == True:
        return True
    else:
        raise VdtTypeError(value)


def is_ip_addr(value):
    """
    Check that the supplied value is an Internet Protocol address, v.4,
    represented by a dotted-quad string, i.e. '1.2.3.4'.
    
    >>> vtor.check('ip_addr', '1 ')
    '1'
    >>> vtor.check('ip_addr', ' 1.2')
    '1.2'
    >>> vtor.check('ip_addr', ' 1.2.3 ')
    '1.2.3'
    >>> vtor.check('ip_addr', '1.2.3.4')
    '1.2.3.4'
    >>> vtor.check('ip_addr', '0.0.0.0')
    '0.0.0.0'
    >>> vtor.check('ip_addr', '255.255.255.255')
    '255.255.255.255'
    >>> vtor.check('ip_addr', '255.255.255.256')
    Traceback (most recent call last):
    VdtValueError: the value "255.255.255.256" is unacceptable.
    >>> vtor.check('ip_addr', '1.2.3.4.5')
    Traceback (most recent call last):
    VdtValueError: the value "1.2.3.4.5" is unacceptable.
    >>> vtor.check('ip_addr', 0)
    Traceback (most recent call last):
    VdtTypeError: the value "0" is of the wrong type.
    """
    if not isinstance(value, string_type):
        raise VdtTypeError(value)
    value = value.strip()
    try:
        dottedQuadToNum(value)
    except ValueError:
        raise VdtValueError(value)
    return value


def is_list(value, min=None, max=None):
    """
    Check that the value is a list of values.
    
    You can optionally specify the minimum and maximum number of members.
    
    It does no check on list members.
    
    >>> vtor.check('list', ())
    []
    >>> vtor.check('list', [])
    []
    >>> vtor.check('list', (1, 2))
    [1, 2]
    >>> vtor.check('list', [1, 2])
    [1, 2]
    >>> vtor.check('list(3)', (1, 2))
    Traceback (most recent call last):
    VdtValueTooShortError: the value "(1, 2)" is too short.
    >>> vtor.check('list(max=5)', (1, 2, 3, 4, 5, 6))
    Traceback (most recent call last):
    VdtValueTooLongError: the value "(1, 2, 3, 4, 5, 6)" is too long.
    >>> vtor.check('list(min=3, max=5)', (1, 2, 3, 4))
    [1, 2, 3, 4]
    >>> vtor.check('list', 0)
    Traceback (most recent call last):
    VdtTypeError: the value "0" is of the wrong type.
    >>> vtor.check('list', '12')
    Traceback (most recent call last):
    VdtTypeError: the value "12" is of the wrong type.
    """
    (min_len, max_len) = _is_num_param(('min', 'max'), (min, max))
    if isinstance(value, string_type):
        raise VdtTypeError(value)
    try:
        num_members = len(value)
    except TypeError:
        raise VdtTypeError(value)
    if min_len is not None and num_members < min_len:
        raise VdtValueTooShortError(value)
    if max_len is not None and num_members > max_len:
        raise VdtValueTooLongError(value)
    return list(value)


def is_tuple(value, min=None, max=None):
    """
    Check that the value is a tuple of values.
    
    You can optionally specify the minimum and maximum number of members.
    
    It does no check on members.
    
    >>> vtor.check('tuple', ())
    ()
    >>> vtor.check('tuple', [])
    ()
    >>> vtor.check('tuple', (1, 2))
    (1, 2)
    >>> vtor.check('tuple', [1, 2])
    (1, 2)
    >>> vtor.check('tuple(3)', (1, 2))
    Traceback (most recent call last):
    VdtValueTooShortError: the value "(1, 2)" is too short.
    >>> vtor.check('tuple(max=5)', (1, 2, 3, 4, 5, 6))
    Traceback (most recent call last):
    VdtValueTooLongError: the value "(1, 2, 3, 4, 5, 6)" is too long.
    >>> vtor.check('tuple(min=3, max=5)', (1, 2, 3, 4))
    (1, 2, 3, 4)
    >>> vtor.check('tuple', 0)
    Traceback (most recent call last):
    VdtTypeError: the value "0" is of the wrong type.
    >>> vtor.check('tuple', '12')
    Traceback (most recent call last):
    VdtTypeError: the value "12" is of the wrong type.
    """
    return tuple(is_list(value, min, max))


def is_string(value, min=None, max=None):
    """
    Check that the supplied value is a string.
    
    You can optionally specify the minimum and maximum number of members.
    
    >>> vtor.check('string', '0')
    '0'
    >>> vtor.check('string', 0)
    Traceback (most recent call last):
    VdtTypeError: the value "0" is of the wrong type.
    >>> vtor.check('string(2)', '12')
    '12'
    >>> vtor.check('string(2)', '1')
    Traceback (most recent call last):
    VdtValueTooShortError: the value "1" is too short.
    >>> vtor.check('string(min=2, max=3)', '123')
    '123'
    >>> vtor.check('string(min=2, max=3)', '1234')
    Traceback (most recent call last):
    VdtValueTooLongError: the value "1234" is too long.
    """
    if not isinstance(value, string_type):
        raise VdtTypeError(value)
    (min_len, max_len) = _is_num_param(('min', 'max'), (min, max))
    try:
        num_members = len(value)
    except TypeError:
        raise VdtTypeError(value)
    if min_len is not None and num_members < min_len:
        raise VdtValueTooShortError(value)
    if max_len is not None and num_members > max_len:
        raise VdtValueTooLongError(value)
    return value


def is_int_list(value, min=None, max=None):
    """
    Check that the value is a list of integers.
    
    You can optionally specify the minimum and maximum number of members.
    
    Each list member is checked that it is an integer.
    
    >>> vtor.check('int_list', ())
    []
    >>> vtor.check('int_list', [])
    []
    >>> vtor.check('int_list', (1, 2))
    [1, 2]
    >>> vtor.check('int_list', [1, 2])
    [1, 2]
    >>> vtor.check('int_list', [1, 'a'])
    Traceback (most recent call last):
    VdtTypeError: the value "a" is of the wrong type.
    """
    return [is_integer(mem) for mem in is_list(value, min, max)]


def is_bool_list(value, min=None, max=None):
    """
    Check that the value is a list of booleans.
    
    You can optionally specify the minimum and maximum number of members.
    
    Each list member is checked that it is a boolean.
    
    >>> vtor.check('bool_list', ())
    []
    >>> vtor.check('bool_list', [])
    []
    >>> check_res = vtor.check('bool_list', (True, False))
    >>> check_res == [True, False]
    1
    >>> check_res = vtor.check('bool_list', [True, False])
    >>> check_res == [True, False]
    1
    >>> vtor.check('bool_list', [True, 'a'])
    Traceback (most recent call last):
    VdtTypeError: the value "a" is of the wrong type.
    """
    return [is_boolean(mem) for mem in is_list(value, min, max)]


def is_float_list(value, min=None, max=None):
    """
    Check that the value is a list of floats.
    
    You can optionally specify the minimum and maximum number of members.
    
    Each list member is checked that it is a float.
    
    >>> vtor.check('float_list', ())
    []
    >>> vtor.check('float_list', [])
    []
    >>> vtor.check('float_list', (1, 2.0))
    [1.0, 2.0]
    >>> vtor.check('float_list', [1, 2.0])
    [1.0, 2.0]
    >>> vtor.check('float_list', [1, 'a'])
    Traceback (most recent call last):
    VdtTypeError: the value "a" is of the wrong type.
    """
    return [is_float(mem) for mem in is_list(value, min, max)]


def is_string_list(value, min=None, max=None):
    """
    Check that the value is a list of strings.
    
    You can optionally specify the minimum and maximum number of members.
    
    Each list member is checked that it is a string.
    
    >>> vtor.check('string_list', ())
    []
    >>> vtor.check('string_list', [])
    []
    >>> vtor.check('string_list', ('a', 'b'))
    ['a', 'b']
    >>> vtor.check('string_list', ['a', 1])
    Traceback (most recent call last):
    VdtTypeError: the value "1" is of the wrong type.
    >>> vtor.check('string_list', 'hello')
    Traceback (most recent call last):
    VdtTypeError: the value "hello" is of the wrong type.
    """
    if isinstance(value, string_type):
        raise VdtTypeError(value)
    return [is_string(mem) for mem in is_list(value, min, max)]


def is_ip_addr_list(value, min=None, max=None):
    """
    Check that the value is a list of IP addresses.
    
    You can optionally specify the minimum and maximum number of members.
    
    Each list member is checked that it is an IP address.
    
    >>> vtor.check('ip_addr_list', ())
    []
    >>> vtor.check('ip_addr_list', [])
    []
    >>> vtor.check('ip_addr_list', ('1.2.3.4', '5.6.7.8'))
    ['1.2.3.4', '5.6.7.8']
    >>> vtor.check('ip_addr_list', ['a'])
    Traceback (most recent call last):
    VdtValueError: the value "a" is unacceptable.
    """
    return [is_ip_addr(mem) for mem in is_list(value, min, max)]


def force_list(value, min=None, max=None):
    """
    Check that a value is a list, coercing strings into
    a list with one member. Useful where users forget the
    trailing comma that turns a single value into a list.
    
    You can optionally specify the minimum and maximum number of members.
    A minumum of greater than one will fail if the user only supplies a
    string.
    
    >>> vtor.check('force_list', ())
    []
    >>> vtor.check('force_list', [])
    []
    >>> vtor.check('force_list', 'hello')
    ['hello']
    """
    if not isinstance(value, (list, tuple)):
        value = [value]
    return is_list(value, min, max)
    
    

fun_dict = {
    'integer': is_integer,
    'float': is_float,
    'ip_addr': is_ip_addr,
    'string': is_string,
    'boolean': is_boolean,
}


def is_mixed_list(value, *args):
    """
    Check that the value is a list.
    Allow specifying the type of each member.
    Work on lists of specific lengths.
    
    You specify each member as a positional argument specifying type
    
    Each type should be one of the following strings :
      'integer', 'float', 'ip_addr', 'string', 'boolean'
    
    So you can specify a list of two strings, followed by
    two integers as :
    
      mixed_list('string', 'string', 'integer', 'integer')
    
    The length of the list must match the number of positional
    arguments you supply.
    
    >>> mix_str = "mixed_list('integer', 'float', 'ip_addr', 'string', 'boolean')"
    >>> check_res = vtor.check(mix_str, (1, 2.0, '1.2.3.4', 'a', True))
    >>> check_res == [1, 2.0, '1.2.3.4', 'a', True]
    1
    >>> check_res = vtor.check(mix_str, ('1', '2.0', '1.2.3.4', 'a', 'True'))
    >>> check_res == [1, 2.0, '1.2.3.4', 'a', True]
    1
    >>> vtor.check(mix_str, ('b', 2.0, '1.2.3.4', 'a', True))
    Traceback (most recent call last):
    VdtTypeError: the value "b" is of the wrong type.
    >>> vtor.check(mix_str, (1, 2.0, '1.2.3.4', 'a'))
    Traceback (most recent call last):
    VdtValueTooShortError: the value "(1, 2.0, '1.2.3.4', 'a')" is too short.
    >>> vtor.check(mix_str, (1, 2.0, '1.2.3.4', 'a', 1, 'b'))
    Traceback (most recent call last):
    VdtValueTooLongError: the value "(1, 2.0, '1.2.3.4', 'a', 1, 'b')" is too long.
    >>> vtor.check(mix_str, 0)
    Traceback (most recent call last):
    VdtTypeError: the value "0" is of the wrong type.

    >>> vtor.check('mixed_list("yoda")', ('a'))
    Traceback (most recent call last):
    VdtParamError: passed an incorrect value "KeyError('yoda',)" for parameter "'mixed_list'"
    """
    try:
        length = len(value)
    except TypeError:
        raise VdtTypeError(value)
    if length < len(args):
        raise VdtValueTooShortError(value)
    elif length > len(args):
        raise VdtValueTooLongError(value)
    try:
        return [fun_dict[arg](val) for arg, val in zip(args, value)]
    except KeyError as e:
        raise VdtParamError('mixed_list', e)


def is_option(value, *options):
    """
    This check matches the value to any of a set of options.
    
    >>> vtor.check('option("yoda", "jedi")', 'yoda')
    'yoda'
    >>> vtor.check('option("yoda", "jedi")', 'jed')
    Traceback (most recent call last):
    VdtValueError: the value "jed" is unacceptable.
    >>> vtor.check('option("yoda", "jedi")', 0)
    Traceback (most recent call last):
    VdtTypeError: the value "0" is of the wrong type.
    """
    if not isinstance(value, string_type):
        raise VdtTypeError(value)
    if not value in options:
        raise VdtValueError(value)
    return value


def _test(value, *args, **keywargs):
    """
    A function that exists for test purposes.
    
    >>> checks = [
    ...     '3, 6, min=1, max=3, test=list(a, b, c)',
    ...     '3',
    ...     '3, 6',
    ...     '3,',
    ...     'min=1, test="a b c"',
    ...     'min=5, test="a, b, c"',
    ...     'min=1, max=3, test="a, b, c"',
    ...     'min=-100, test=-99',
    ...     'min=1, max=3',
    ...     '3, 6, test="36"',
    ...     '3, 6, test="a, b, c"',
    ...     '3, max=3, test=list("a", "b", "c")',
    ...     '''3, max=3, test=list("'a'", 'b', "x=(c)")''',
    ...     "test='x=fish(3)'",
    ...    ]
    >>> v = Validator({'test': _test})
    >>> for entry in checks:
    ...     pprint(v.check(('test(%s)' % entry), 3))
    (3, ('3', '6'), {'max': '3', 'min': '1', 'test': ['a', 'b', 'c']})
    (3, ('3',), {})
    (3, ('3', '6'), {})
    (3, ('3',), {})
    (3, (), {'min': '1', 'test': 'a b c'})
    (3, (), {'min': '5', 'test': 'a, b, c'})
    (3, (), {'max': '3', 'min': '1', 'test': 'a, b, c'})
    (3, (), {'min': '-100', 'test': '-99'})
    (3, (), {'max': '3', 'min': '1'})
    (3, ('3', '6'), {'test': '36'})
    (3, ('3', '6'), {'test': 'a, b, c'})
    (3, ('3',), {'max': '3', 'test': ['a', 'b', 'c']})
    (3, ('3',), {'max': '3', 'test': ["'a'", 'b', 'x=(c)']})
    (3, (), {'test': 'x=fish(3)'})
    
    >>> v = Validator()
    >>> v.check('integer(default=6)', '3')
    3
    >>> v.check('integer(default=6)', None, True)
    6
    >>> v.get_default_value('integer(default=6)')
    6
    >>> v.get_default_value('float(default=6)')
    6.0
    >>> v.get_default_value('pass(default=None)')
    >>> v.get_default_value("string(default='None')")
    'None'
    >>> v.get_default_value('pass')
    Traceback (most recent call last):
    KeyError: 'Check "pass" has no default value.'
    >>> v.get_default_value('pass(default=list(1, 2, 3, 4))')
    ['1', '2', '3', '4']
    
    >>> v = Validator()
    >>> v.check("pass(default=None)", None, True)
    >>> v.check("pass(default='None')", None, True)
    'None'
    >>> v.check('pass(default="None")', None, True)
    'None'
    >>> v.check('pass(default=list(1, 2, 3, 4))', None, True)
    ['1', '2', '3', '4']
    
    Bug test for unicode arguments
    >>> v = Validator()
    >>> v.check(unicode('string(min=4)'), unicode('test')) == unicode('test')
    True
    
    >>> v = Validator()
    >>> v.get_default_value(unicode('string(min=4, default="1234")')) == unicode('1234')
    True
    >>> v.check(unicode('string(min=4, default="1234")'), unicode('test')) == unicode('test')
    True
    
    >>> v = Validator()
    >>> default = v.get_default_value('string(default=None)')
    >>> default == None
    1
    """
    return (value, args, keywargs)


def _test2():
    """
    >>> 
    >>> v = Validator()
    >>> v.get_default_value('string(default="#ff00dd")')
    '#ff00dd'
    >>> v.get_default_value('integer(default=3) # comment')
    3
    """

def _test3():
    r"""
    >>> vtor.check('string(default="")', '', missing=True)
    ''
    >>> vtor.check('string(default="\n")', '', missing=True)
    '\n'
    >>> print(vtor.check('string(default="\n")', '', missing=True))
    <BLANKLINE>
    <BLANKLINE>
    >>> vtor.check('string()', '\n')
    '\n'
    >>> vtor.check('string(default="\n\n\n")', '', missing=True)
    '\n\n\n'
    >>> vtor.check('string()', 'random \n text goes here\n\n')
    'random \n text goes here\n\n'
    >>> vtor.check('string(default=" \nrandom text\ngoes \n here\n\n ")',
    ... '', missing=True)
    ' \nrandom text\ngoes \n here\n\n '
    >>> vtor.check("string(default='\n\n\n')", '', missing=True)
    '\n\n\n'
    >>> vtor.check("option('\n','a','b',default='\n')", '', missing=True)
    '\n'
    >>> vtor.check("string_list()", ['foo', '\n', 'bar'])
    ['foo', '\n', 'bar']
    >>> vtor.check("string_list(default=list('\n'))", '', missing=True)
    ['\n']
    """
    
    
if __name__ == '__main__':
    # run the code tests in doctest format
    import sys
    import doctest
    m = sys.modules.get('__main__')
    globs = m.__dict__.copy()
    globs.update({
        'vtor': Validator(),
    })

    failures, tests = doctest.testmod(
        m, globs=globs,
        optionflags=doctest.IGNORE_EXCEPTION_DETAIL | doctest.ELLIPSIS)
    assert not failures, '{} failures out of {} tests'.format(failures, tests)
