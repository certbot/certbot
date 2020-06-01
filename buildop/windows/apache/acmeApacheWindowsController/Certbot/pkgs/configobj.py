# configobj.py
# A config file reader/writer that supports nested sections in config files.
# Copyright (C) 2005-2014:
# (name) : (email)
# Michael Foord: fuzzyman AT voidspace DOT org DOT uk
# Nicola Larosa: nico AT tekNico DOT net
# Rob Dennis: rdennis AT gmail DOT com
# Eli Courtwright: eli AT courtwright DOT org

# This software is licensed under the terms of the BSD license.
# http://opensource.org/licenses/BSD-3-Clause

# ConfigObj 5 - main repository for documentation and issue tracking:
# https://github.com/DiffSK/configobj

import os
import re
import sys

from codecs import BOM_UTF8, BOM_UTF16, BOM_UTF16_BE, BOM_UTF16_LE

import six
from _version import __version__

# imported lazily to avoid startup performance hit if it isn't used
compiler = None

# A dictionary mapping BOM to
# the encoding to decode with, and what to set the
# encoding attribute to.
BOMS = {
    BOM_UTF8: ('utf_8', None),
    BOM_UTF16_BE: ('utf16_be', 'utf_16'),
    BOM_UTF16_LE: ('utf16_le', 'utf_16'),
    BOM_UTF16: ('utf_16', 'utf_16'),
    }
# All legal variants of the BOM codecs.
# TODO: the list of aliases is not meant to be exhaustive, is there a
#   better way ?
BOM_LIST = {
    'utf_16': 'utf_16',
    'u16': 'utf_16',
    'utf16': 'utf_16',
    'utf-16': 'utf_16',
    'utf16_be': 'utf16_be',
    'utf_16_be': 'utf16_be',
    'utf-16be': 'utf16_be',
    'utf16_le': 'utf16_le',
    'utf_16_le': 'utf16_le',
    'utf-16le': 'utf16_le',
    'utf_8': 'utf_8',
    'u8': 'utf_8',
    'utf': 'utf_8',
    'utf8': 'utf_8',
    'utf-8': 'utf_8',
    }

# Map of encodings to the BOM to write.
BOM_SET = {
    'utf_8': BOM_UTF8,
    'utf_16': BOM_UTF16,
    'utf16_be': BOM_UTF16_BE,
    'utf16_le': BOM_UTF16_LE,
    None: BOM_UTF8
    }


def match_utf8(encoding):
    return BOM_LIST.get(encoding.lower()) == 'utf_8'


# Quote strings used for writing values
squot = "'%s'"
dquot = '"%s"'
noquot = "%s"
wspace_plus = ' \r\n\v\t\'"'
tsquot = '"""%s"""'
tdquot = "'''%s'''"

# Sentinel for use in getattr calls to replace hasattr
MISSING = object()

__all__ = (
    'DEFAULT_INDENT_TYPE',
    'DEFAULT_INTERPOLATION',
    'ConfigObjError',
    'NestingError',
    'ParseError',
    'DuplicateError',
    'ConfigspecError',
    'ConfigObj',
    'SimpleVal',
    'InterpolationError',
    'InterpolationLoopError',
    'MissingInterpolationOption',
    'RepeatSectionError',
    'ReloadError',
    'UnreprError',
    'UnknownType',
    'flatten_errors',
    'get_extra_values'
)

DEFAULT_INTERPOLATION = 'configparser'
DEFAULT_INDENT_TYPE = '    '
MAX_INTERPOL_DEPTH = 10

OPTION_DEFAULTS = {
    'interpolation': True,
    'raise_errors': False,
    'list_values': True,
    'create_empty': False,
    'file_error': False,
    'configspec': None,
    'stringify': True,
    # option may be set to one of ('', ' ', '\t')
    'indent_type': None,
    'encoding': None,
    'default_encoding': None,
    'unrepr': False,
    'write_empty_values': False,
}

# this could be replaced if six is used for compatibility, or there are no
# more assertions about items being a string


def getObj(s):
    global compiler
    if compiler is None:
        import compiler
    s = "a=" + s
    p = compiler.parse(s)
    return p.getChildren()[1].getChildren()[0].getChildren()[1]


class UnknownType(Exception):
    pass


class Builder(object):
    
    def build(self, o):
        if m is None:
            raise UnknownType(o.__class__.__name__)
        return m(o)
    
    def build_List(self, o):
        return list(map(self.build, o.getChildren()))
    
    def build_Const(self, o):
        return o.value
    
    def build_Dict(self, o):
        d = {}
        i = iter(map(self.build, o.getChildren()))
        for el in i:
            d[el] = next(i)
        return d
    
    def build_Tuple(self, o):
        return tuple(self.build_List(o))
    
    def build_Name(self, o):
        if o.name == 'None':
            return None
        if o.name == 'True':
            return True
        if o.name == 'False':
            return False
        
        # An undefined Name
        raise UnknownType('Undefined Name')
    
    def build_Add(self, o):
        real, imag = list(map(self.build_Const, o.getChildren()))
        try:
            real = float(real)
        except TypeError:
            raise UnknownType('Add')
        if not isinstance(imag, complex) or imag.real != 0.0:
            raise UnknownType('Add')
        return real+imag
    
    def build_Getattr(self, o):
        parent = self.build(o.expr)
        return getattr(parent, o.attrname)
    
    def build_UnarySub(self, o):
        return -self.build_Const(o.getChildren()[0])
    
    def build_UnaryAdd(self, o):
        return self.build_Const(o.getChildren()[0])


_builder = Builder()


def unrepr(s):
    if not s:
        return s
    
    # this is supposed to be safe
    import ast
    return ast.literal_eval(s)


class ConfigObjError(SyntaxError):
    """
    This is the base class for all errors that ConfigObj raises.
    It is a subclass of SyntaxError.
    """
    def __init__(self, message='', line_number=None, line=''):
        self.line = line
        self.line_number = line_number
        SyntaxError.__init__(self, message)


class NestingError(ConfigObjError):
    """
    This error indicates a level of nesting that doesn't match.
    """


class ParseError(ConfigObjError):
    """
    This error indicates that a line is badly written.
    It is neither a valid ``key = value`` line,
    nor a valid section marker line.
    """


class ReloadError(IOError):
    """
    A 'reload' operation failed.
    This exception is a subclass of ``IOError``.
    """
    def __init__(self):
        IOError.__init__(self, 'reload failed, filename is not set.')


class DuplicateError(ConfigObjError):
    """
    The keyword or section specified already exists.
    """


class ConfigspecError(ConfigObjError):
    """
    An error occured whilst parsing a configspec.
    """


class InterpolationError(ConfigObjError):
    """Base class for the two interpolation errors."""


class InterpolationLoopError(InterpolationError):
    """Maximum interpolation depth exceeded in string interpolation."""

    def __init__(self, option):
        InterpolationError.__init__(
            self,
            'interpolation loop detected in value "%s".' % option)


class RepeatSectionError(ConfigObjError):
    """
    This error indicates additional sections in a section with a
    ``__many__`` (repeated) section.
    """


class MissingInterpolationOption(InterpolationError):
    """A value specified for interpolation was missing."""
    def __init__(self, option):
        msg = 'missing option "%s" in interpolation.' % option
        InterpolationError.__init__(self, msg)


class UnreprError(ConfigObjError):
    """An error parsing in unrepr mode."""



class InterpolationEngine(object):
    """
    A helper class to help perform string interpolation.

    This class is an abstract base class; its descendants perform
    the actual work.
    """

    # compiled regexp to use in self.interpolate()
    _KEYCRE = re.compile(r"%\(([^)]*)\)s")
    _cookie = '%'

    def __init__(self, section):
        # the Section instance that "owns" this engine
        self.section = section


    def interpolate(self, key, value):
        # short-cut
        if not self._cookie in value:
            return value
        
        def recursive_interpolate(key, value, section, backtrail):
            """The function that does the actual work.

            ``value``: the string we're trying to interpolate.
            ``section``: the section in which that string was found
            ``backtrail``: a dict to keep track of where we've been,
            to detect and prevent infinite recursion loops

            This is similar to a depth-first-search algorithm.
            """
            # Have we been here already?
            if (key, section.name) in backtrail:
                # Yes - infinite loop detected
                raise InterpolationLoopError(key)
            # Place a marker on our backtrail so we won't come back here again
            backtrail[(key, section.name)] = 1

            # Now start the actual work
            match = self._KEYCRE.search(value)
            while match:
                # The actual parsing of the match is implementation-dependent,
                # so delegate to our helper function
                k, v, s = self._parse_match(match)
                if k is None:
                    # That's the signal that no further interpolation is needed
                    replacement = v
                else:
                    # Further interpolation may be needed to obtain final value
                    replacement = recursive_interpolate(k, v, s, backtrail)
                # Replace the matched string with its final value
                start, end = match.span()
                value = ''.join((value[:start], replacement, value[end:]))
                new_search_start = start + len(replacement)
                # Pick up the next interpolation key, if any, for next time
                # through the while loop
                match = self._KEYCRE.search(value, new_search_start)

            # Now safe to come back here again; remove marker from backtrail
            del backtrail[(key, section.name)]

            return value

        # Back in interpolate(), all we have to do is kick off the recursive
        # function with appropriate starting values
        value = recursive_interpolate(key, value, self.section, {})
        return value


    def _fetch(self, key):
        """Helper function to fetch values from owning section.

        Returns a 2-tuple: the value, and the section where it was found.
        """
        # switch off interpolation before we try and fetch anything !
        save_interp = self.section.main.interpolation
        self.section.main.interpolation = False

        # Start at section that "owns" this InterpolationEngine
        current_section = self.section
        while True:
            # try the current section first
            val = current_section.get(key)
            if val is not None and not isinstance(val, Section):
                break
            # try "DEFAULT" next
            val = current_section.get('DEFAULT', {}).get(key)
            if val is not None and not isinstance(val, Section):
                break
            # move up to parent and try again
            # top-level's parent is itself
            if current_section.parent is current_section:
                # reached top level, time to give up
                break
            current_section = current_section.parent

        # restore interpolation to previous value before returning
        self.section.main.interpolation = save_interp
        if val is None:
            raise MissingInterpolationOption(key)
        return val, current_section


    def _parse_match(self, match):
        """Implementation-dependent helper function.

        Will be passed a match object corresponding to the interpolation
        key we just found (e.g., "%(foo)s" or "$foo"). Should look up that
        key in the appropriate config file section (using the ``_fetch()``
        helper function) and return a 3-tuple: (key, value, section)

        ``key`` is the name of the key we're looking for
        ``value`` is the value found for that key
        ``section`` is a reference to the section where it was found

        ``key`` and ``section`` should be None if no further
        interpolation should be performed on the resulting value
        (e.g., if we interpolated "$$" and returned "$").
        """
        raise NotImplementedError()
    


class ConfigParserInterpolation(InterpolationEngine):
    """Behaves like ConfigParser."""
    _cookie = '%'
    _KEYCRE = re.compile(r"%\(([^)]*)\)s")

    def _parse_match(self, match):
        key = match.group(1)
        value, section = self._fetch(key)
        return key, value, section



class TemplateInterpolation(InterpolationEngine):
    """Behaves like string.Template."""
    _cookie = '$'
    _delimiter = '$'
    _KEYCRE = re.compile(r"""
        \$(?:
          (?P<escaped>\$)              |   # Two $ signs
          (?P<named>[_a-z][_a-z0-9]*)  |   # $name format
          {(?P<braced>[^}]*)}              # ${name} format
        )
        """, re.IGNORECASE | re.VERBOSE)

    def _parse_match(self, match):
        # Valid name (in or out of braces): fetch value from section
        key = match.group('named') or match.group('braced')
        if key is not None:
            value, section = self._fetch(key)
            return key, value, section
        # Escaped delimiter (e.g., $$): return single delimiter
        if match.group('escaped') is not None:
            # Return None for key and section to indicate it's time to stop
            return None, self._delimiter, None
        # Anything else: ignore completely, just return it unchanged
        return None, match.group(), None


interpolation_engines = {
    'configparser': ConfigParserInterpolation,
    'template': TemplateInterpolation,
}


def __newobj__(cls, *args):
    # Hack for pickle
    return cls.__new__(cls, *args) 

class Section(dict):
    """
    A dictionary-like object that represents a section in a config file.
    
    It does string interpolation if the 'interpolation' attribute
    of the 'main' object is set to True.
    
    Interpolation is tried first from this object, then from the 'DEFAULT'
    section of this object, next from the parent and its 'DEFAULT' section,
    and so on until the main object is reached.
    
    A Section will behave like an ordered dictionary - following the
    order of the ``scalars`` and ``sections`` attributes.
    You can use this to change the order of members.
    
    Iteration follows the order: scalars, then sections.
    """

    
    def __setstate__(self, state):
        dict.update(self, state[0])
        self.__dict__.update(state[1])

    def __reduce__(self):
        state = (dict(self), self.__dict__)
        return (__newobj__, (self.__class__,), state)
    
    
    def __init__(self, parent, depth, main, indict=None, name=None):
        """
        * parent is the section above
        * depth is the depth level of this section
        * main is the main ConfigObj
        * indict is a dictionary to initialise the section with
        """
        if indict is None:
            indict = {}
        dict.__init__(self)
        # used for nesting level *and* interpolation
        self.parent = parent
        # used for the interpolation attribute
        self.main = main
        # level of nesting depth of this Section
        self.depth = depth
        # purely for information
        self.name = name
        #
        self._initialise()
        # we do this explicitly so that __setitem__ is used properly
        # (rather than just passing to ``dict.__init__``)
        for entry, value in indict.items():
            self[entry] = value
            
            
    def _initialise(self):
        # the sequence of scalar values in this Section
        self.scalars = []
        # the sequence of sections in this Section
        self.sections = []
        # for comments :-)
        self.comments = {}
        self.inline_comments = {}
        # the configspec
        self.configspec = None
        # for defaults
        self.defaults = []
        self.default_values = {}
        self.extra_values = []
        self._created = False


    def _interpolate(self, key, value):
        try:
            # do we already have an interpolation engine?
            engine = self._interpolation_engine
        except AttributeError:
            # not yet: first time running _interpolate(), so pick the engine
            name = self.main.interpolation
            if name == True:  # note that "if name:" would be incorrect here
                # backwards-compatibility: interpolation=True means use default
                name = DEFAULT_INTERPOLATION
            name = name.lower()  # so that "Template", "template", etc. all work
            class_ = interpolation_engines.get(name, None)
            if class_ is None:
                # invalid value for self.main.interpolation
                self.main.interpolation = False
                return value
            else:
                # save reference to engine so we don't have to do this again
                engine = self._interpolation_engine = class_(self)
        # let the engine do the actual work
        return engine.interpolate(key, value)


    def __getitem__(self, key):
        """Fetch the item and do string interpolation."""
        val = dict.__getitem__(self, key)
        if self.main.interpolation: 
            if isinstance(val, six.string_types):
                return self._interpolate(key, val)
            if isinstance(val, list):
                def _check(entry):
                    if isinstance(entry, six.string_types):
                        return self._interpolate(key, entry)
                    return entry
                new = [_check(entry) for entry in val]
                if new != val:
                    return new
        return val


    def __setitem__(self, key, value, unrepr=False):
        """
        Correctly set a value.
        
        Making dictionary values Section instances.
        (We have to special case 'Section' instances - which are also dicts)
        
        Keys must be strings.
        Values need only be strings (or lists of strings) if
        ``main.stringify`` is set.
        
        ``unrepr`` must be set when setting a value to a dictionary, without
        creating a new sub-section.
        """
        if not isinstance(key, six.string_types):
            raise ValueError('The key "%s" is not a string.' % key)
        
        # add the comment
        if key not in self.comments:
            self.comments[key] = []
            self.inline_comments[key] = ''
        # remove the entry from defaults
        if key in self.defaults:
            self.defaults.remove(key)
        #
        if isinstance(value, Section):
            if key not in self:
                self.sections.append(key)
            dict.__setitem__(self, key, value)
        elif isinstance(value, dict) and not unrepr:
            # First create the new depth level,
            # then create the section
            if key not in self:
                self.sections.append(key)
            new_depth = self.depth + 1
            dict.__setitem__(
                self,
                key,
                Section(
                    self,
                    new_depth,
                    self.main,
                    indict=value,
                    name=key))
        else:
            if key not in self:
                self.scalars.append(key)
            if not self.main.stringify:
                if isinstance(value, six.string_types):
                    pass
                elif isinstance(value, (list, tuple)):
                    for entry in value:
                        if not isinstance(entry, six.string_types):
                            raise TypeError('Value is not a string "%s".' % entry)
                else:
                    raise TypeError('Value is not a string "%s".' % value)
            dict.__setitem__(self, key, value)


    def __delitem__(self, key):
        """Remove items from the sequence when deleting."""
        dict. __delitem__(self, key)
        if key in self.scalars:
            self.scalars.remove(key)
        else:
            self.sections.remove(key)
        del self.comments[key]
        del self.inline_comments[key]


    def get(self, key, default=None):
        """A version of ``get`` that doesn't bypass string interpolation."""
        try:
            return self[key]
        except KeyError:
            return default


    def update(self, indict):
        """
        A version of update that uses our ``__setitem__``.
        """
        for entry in indict:
            self[entry] = indict[entry]


    def pop(self, key, default=MISSING):
        """
        'D.pop(k[,d]) -> v, remove specified key and return the corresponding value.
        If key is not found, d is returned if given, otherwise KeyError is raised'
        """
        try:
            val = self[key]
        except KeyError:
            if default is MISSING:
                raise
            val = default
        else:
            del self[key]
        return val


    def popitem(self):
        """Pops the first (key,val)"""
        sequence = (self.scalars + self.sections)
        if not sequence:
            raise KeyError(": 'popitem(): dictionary is empty'")
        key = sequence[0]
        val =  self[key]
        del self[key]
        return key, val


    def clear(self):
        """
        A version of clear that also affects scalars/sections
        Also clears comments and configspec.
        
        Leaves other attributes alone :
            depth/main/parent are not affected
        """
        dict.clear(self)
        self.scalars = []
        self.sections = []
        self.comments = {}
        self.inline_comments = {}
        self.configspec = None
        self.defaults = []
        self.extra_values = []


    def setdefault(self, key, default=None):
        """A version of setdefault that sets sequence if appropriate."""
        try:
            return self[key]
        except KeyError:
            self[key] = default
            return self[key]


    def items(self):
        """D.items() -> list of D's (key, value) pairs, as 2-tuples"""
        return list(zip((self.scalars + self.sections), list(self.values())))


    def keys(self):
        """D.keys() -> list of D's keys"""
        return (self.scalars + self.sections)


    def values(self):
        """D.values() -> list of D's values"""
        return [self[key] for key in (self.scalars + self.sections)]


    def iteritems(self):
        """D.iteritems() -> an iterator over the (key, value) items of D"""
        return iter(list(self.items()))


    def iterkeys(self):
        """D.iterkeys() -> an iterator over the keys of D"""
        return iter((self.scalars + self.sections))

    __iter__ = iterkeys


    def itervalues(self):
        """D.itervalues() -> an iterator over the values of D"""
        return iter(list(self.values()))


    def __repr__(self):
        """x.__repr__() <==> repr(x)"""
        def _getval(key):
            try:
                return self[key]
            except MissingInterpolationOption:
                return dict.__getitem__(self, key)
        return '{%s}' % ', '.join([('%s: %s' % (repr(key), repr(_getval(key))))
            for key in (self.scalars + self.sections)])

    __str__ = __repr__
    __str__.__doc__ = "x.__str__() <==> str(x)"


    # Extra methods - not in a normal dictionary

    def dict(self):
        """
        Return a deepcopy of self as a dictionary.
        
        All members that are ``Section`` instances are recursively turned to
        ordinary dictionaries - by calling their ``dict`` method.
        
        >>> n = a.dict()
        >>> n == a
        1
        >>> n is a
        0
        """
        newdict = {}
        for entry in self:
            this_entry = self[entry]
            if isinstance(this_entry, Section):
                this_entry = this_entry.dict()
            elif isinstance(this_entry, list):
                # create a copy rather than a reference
                this_entry = list(this_entry)
            elif isinstance(this_entry, tuple):
                # create a copy rather than a reference
                this_entry = tuple(this_entry)
            newdict[entry] = this_entry
        return newdict


    def merge(self, indict):
        """
        A recursive update - useful for merging config files.
        
        >>> a = '''[section1]
        ...     option1 = True
        ...     [[subsection]]
        ...     more_options = False
        ...     # end of file'''.splitlines()
        >>> b = '''# File is user.ini
        ...     [section1]
        ...     option1 = False
        ...     # end of file'''.splitlines()
        >>> c1 = ConfigObj(b)
        >>> c2 = ConfigObj(a)
        >>> c2.merge(c1)
        >>> c2
        ConfigObj({'section1': {'option1': 'False', 'subsection': {'more_options': 'False'}}})
        """
        for key, val in list(indict.items()):
            if (key in self and isinstance(self[key], dict) and
                                isinstance(val, dict)):
                self[key].merge(val)
            else:   
                self[key] = val


    def rename(self, oldkey, newkey):
        """
        Change a keyname to another, without changing position in sequence.
        
        Implemented so that transformations can be made on keys,
        as well as on values. (used by encode and decode)
        
        Also renames comments.
        """
        if oldkey in self.scalars:
            the_list = self.scalars
        elif oldkey in self.sections:
            the_list = self.sections
        else:
            raise KeyError('Key "%s" not found.' % oldkey)
        pos = the_list.index(oldkey)
        #
        val = self[oldkey]
        dict.__delitem__(self, oldkey)
        dict.__setitem__(self, newkey, val)
        the_list.remove(oldkey)
        the_list.insert(pos, newkey)
        comm = self.comments[oldkey]
        inline_comment = self.inline_comments[oldkey]
        del self.comments[oldkey]
        del self.inline_comments[oldkey]
        self.comments[newkey] = comm
        self.inline_comments[newkey] = inline_comment


    def walk(self, function, raise_errors=True,
            call_on_sections=False, **keywargs):
        """
        Walk every member and call a function on the keyword and value.
        
        Return a dictionary of the return values
        
        If the function raises an exception, raise the errror
        unless ``raise_errors=False``, in which case set the return value to
        ``False``.
        
        Any unrecognised keyword arguments you pass to walk, will be pased on
        to the function you pass in.
        
        Note: if ``call_on_sections`` is ``True`` then - on encountering a
        subsection, *first* the function is called for the *whole* subsection,
        and then recurses into it's members. This means your function must be
        able to handle strings, dictionaries and lists. This allows you
        to change the key of subsections as well as for ordinary members. The
        return value when called on the whole subsection has to be discarded.
        
        See  the encode and decode methods for examples, including functions.
        
        .. admonition:: caution
        
            You can use ``walk`` to transform the names of members of a section
            but you mustn't add or delete members.
        
        >>> config = '''[XXXXsection]
        ... XXXXkey = XXXXvalue'''.splitlines()
        >>> cfg = ConfigObj(config)
        >>> cfg
        ConfigObj({'XXXXsection': {'XXXXkey': 'XXXXvalue'}})
        >>> def transform(section, key):
        ...     val = section[key]
        ...     newkey = key.replace('XXXX', 'CLIENT1')
        ...     section.rename(key, newkey)
        ...     if isinstance(val, (tuple, list, dict)):
        ...         pass
        ...     else:
        ...         val = val.replace('XXXX', 'CLIENT1')
        ...         section[newkey] = val
        >>> cfg.walk(transform, call_on_sections=True)
        {'CLIENT1section': {'CLIENT1key': None}}
        >>> cfg
        ConfigObj({'CLIENT1section': {'CLIENT1key': 'CLIENT1value'}})
        """
        out = {}
        # scalars first
        for i in range(len(self.scalars)):
            entry = self.scalars[i]
            try:
                val = function(self, entry, **keywargs)
                # bound again in case name has changed
                entry = self.scalars[i]
                out[entry] = val
            except Exception:
                if raise_errors:
                    raise
                else:
                    entry = self.scalars[i]
                    out[entry] = False
        # then sections
        for i in range(len(self.sections)):
            entry = self.sections[i]
            if call_on_sections:
                try:
                    function(self, entry, **keywargs)
                except Exception:
                    if raise_errors:
                        raise
                    else:
                        entry = self.sections[i]
                        out[entry] = False
                # bound again in case name has changed
                entry = self.sections[i]
            # previous result is discarded
            out[entry] = self[entry].walk(
                function,
                raise_errors=raise_errors,
                call_on_sections=call_on_sections,
                **keywargs)
        return out


    def as_bool(self, key):
        """
        Accepts a key as input. The corresponding value must be a string or
        the objects (``True`` or 1) or (``False`` or 0). We allow 0 and 1 to
        retain compatibility with Python 2.2.
        
        If the string is one of  ``True``, ``On``, ``Yes``, or ``1`` it returns 
        ``True``.
        
        If the string is one of  ``False``, ``Off``, ``No``, or ``0`` it returns 
        ``False``.
        
        ``as_bool`` is not case sensitive.
        
        Any other input will raise a ``ValueError``.
        
        >>> a = ConfigObj()
        >>> a['a'] = 'fish'
        >>> a.as_bool('a')
        Traceback (most recent call last):
        ValueError: Value "fish" is neither True nor False
        >>> a['b'] = 'True'
        >>> a.as_bool('b')
        1
        >>> a['b'] = 'off'
        >>> a.as_bool('b')
        0
        """
        val = self[key]
        if val == True:
            return True
        elif val == False:
            return False
        else:
            try:
                if not isinstance(val, six.string_types):
                    # TODO: Why do we raise a KeyError here?
                    raise KeyError()
                else:
                    return self.main._bools[val.lower()]
            except KeyError:
                raise ValueError('Value "%s" is neither True nor False' % val)


    def as_int(self, key):
        """
        A convenience method which coerces the specified value to an integer.
        
        If the value is an invalid literal for ``int``, a ``ValueError`` will
        be raised.
        
        >>> a = ConfigObj()
        >>> a['a'] = 'fish'
        >>> a.as_int('a')
        Traceback (most recent call last):
        ValueError: invalid literal for int() with base 10: 'fish'
        >>> a['b'] = '1'
        >>> a.as_int('b')
        1
        >>> a['b'] = '3.2'
        >>> a.as_int('b')
        Traceback (most recent call last):
        ValueError: invalid literal for int() with base 10: '3.2'
        """
        return int(self[key])


    def as_float(self, key):
        """
        A convenience method which coerces the specified value to a float.
        
        If the value is an invalid literal for ``float``, a ``ValueError`` will
        be raised.
        
        >>> a = ConfigObj()
        >>> a['a'] = 'fish'
        >>> a.as_float('a')  #doctest: +IGNORE_EXCEPTION_DETAIL
        Traceback (most recent call last):
        ValueError: invalid literal for float(): fish
        >>> a['b'] = '1'
        >>> a.as_float('b')
        1.0
        >>> a['b'] = '3.2'
        >>> a.as_float('b')  #doctest: +ELLIPSIS
        3.2...
        """
        return float(self[key])
    
    
    def as_list(self, key):
        """
        A convenience method which fetches the specified value, guaranteeing
        that it is a list.
        
        >>> a = ConfigObj()
        >>> a['a'] = 1
        >>> a.as_list('a')
        [1]
        >>> a['a'] = (1,)
        >>> a.as_list('a')
        [1]
        >>> a['a'] = [1]
        >>> a.as_list('a')
        [1]
        """
        result = self[key]
        if isinstance(result, (tuple, list)):
            return list(result)
        return [result]
        

    def restore_default(self, key):
        """
        Restore (and return) default value for the specified key.
        
        This method will only work for a ConfigObj that was created
        with a configspec and has been validated.
        
        If there is no default value for this key, ``KeyError`` is raised.
        """
        default = self.default_values[key]
        dict.__setitem__(self, key, default)
        if key not in self.defaults:
            self.defaults.append(key)
        return default

    
    def restore_defaults(self):
        """
        Recursively restore default values to all members
        that have them.
        
        This method will only work for a ConfigObj that was created
        with a configspec and has been validated.
        
        It doesn't delete or modify entries without default values.
        """
        for key in self.default_values:
            self.restore_default(key)
            
        for section in self.sections:
            self[section].restore_defaults()


class ConfigObj(Section):
    """An object to read, create, and write config files."""

    _keyword = re.compile(r'''^ # line start
        (\s*)                   # indentation
        (                       # keyword
            (?:".*?")|          # double quotes
            (?:'.*?')|          # single quotes
            (?:[^'"=].*?)       # no quotes
        )
        \s*=\s*                 # divider
        (.*)                    # value (including list values and comments)
        $   # line end
        ''',
        re.VERBOSE)

    _sectionmarker = re.compile(r'''^
        (\s*)                     # 1: indentation
        ((?:\[\s*)+)              # 2: section marker open
        (                         # 3: section name open
            (?:"\s*\S.*?\s*")|    # at least one non-space with double quotes
            (?:'\s*\S.*?\s*')|    # at least one non-space with single quotes
            (?:[^'"\s].*?)        # at least one non-space unquoted
        )                         # section name close
        ((?:\s*\])+)              # 4: section marker close
        \s*(\#.*)?                # 5: optional comment
        $''',
        re.VERBOSE)

    # this regexp pulls list values out as a single string
    # or single values and comments
    # FIXME: this regex adds a '' to the end of comma terminated lists
    #   workaround in ``_handle_value``
    _valueexp = re.compile(r'''^
        (?:
            (?:
                (
                    (?:
                        (?:
                            (?:".*?")|              # double quotes
                            (?:'.*?')|              # single quotes
                            (?:[^'",\#][^,\#]*?)    # unquoted
                        )
                        \s*,\s*                     # comma
                    )*      # match all list items ending in a comma (if any)
                )
                (
                    (?:".*?")|                      # double quotes
                    (?:'.*?')|                      # single quotes
                    (?:[^'",\#\s][^,]*?)|           # unquoted
                    (?:(?<!,))                      # Empty value
                )?          # last item in a list - or string value
            )|
            (,)             # alternatively a single comma - empty list
        )
        \s*(\#.*)?          # optional comment
        $''',
        re.VERBOSE)

    # use findall to get the members of a list value
    _listvalueexp = re.compile(r'''
        (
            (?:".*?")|          # double quotes
            (?:'.*?')|          # single quotes
            (?:[^'",\#]?.*?)       # unquoted
        )
        \s*,\s*                 # comma
        ''',
        re.VERBOSE)

    # this regexp is used for the value
    # when lists are switched off
    _nolistvalue = re.compile(r'''^
        (
            (?:".*?")|          # double quotes
            (?:'.*?')|          # single quotes
            (?:[^'"\#].*?)|     # unquoted
            (?:)                # Empty value
        )
        \s*(\#.*)?              # optional comment
        $''',
        re.VERBOSE)

    # regexes for finding triple quoted values on one line
    _single_line_single = re.compile(r"^'''(.*?)'''\s*(#.*)?$")
    _single_line_double = re.compile(r'^"""(.*?)"""\s*(#.*)?$')
    _multi_line_single = re.compile(r"^(.*?)'''\s*(#.*)?$")
    _multi_line_double = re.compile(r'^(.*?)"""\s*(#.*)?$')

    _triple_quote = {
        "'''": (_single_line_single, _multi_line_single),
        '"""': (_single_line_double, _multi_line_double),
    }

    # Used by the ``istrue`` Section method
    _bools = {
        'yes': True, 'no': False,
        'on': True, 'off': False,
        '1': True, '0': False,
        'true': True, 'false': False,
        }


    def __init__(self, infile=None, options=None, configspec=None, encoding=None,
                 interpolation=True, raise_errors=False, list_values=True,
                 create_empty=False, file_error=False, stringify=True,
                 indent_type=None, default_encoding=None, unrepr=False,
                 write_empty_values=False, _inspec=False):
        """
        Parse a config file or create a config file object.
        
        ``ConfigObj(infile=None, configspec=None, encoding=None,
                    interpolation=True, raise_errors=False, list_values=True,
                    create_empty=False, file_error=False, stringify=True,
                    indent_type=None, default_encoding=None, unrepr=False,
                    write_empty_values=False, _inspec=False)``
        """
        self._inspec = _inspec
        # init the superclass
        Section.__init__(self, self, 0, self)
        
        infile = infile or []
        
        _options = {'configspec': configspec,
                    'encoding': encoding, 'interpolation': interpolation,
                    'raise_errors': raise_errors, 'list_values': list_values,
                    'create_empty': create_empty, 'file_error': file_error,
                    'stringify': stringify, 'indent_type': indent_type,
                    'default_encoding': default_encoding, 'unrepr': unrepr,
                    'write_empty_values': write_empty_values}

        if options is None:
            options = _options
        else:
            import warnings
            warnings.warn('Passing in an options dictionary to ConfigObj() is '
                          'deprecated. Use **options instead.',
                          DeprecationWarning, stacklevel=2)
            
            # TODO: check the values too.
            for entry in options:
                if entry not in OPTION_DEFAULTS:
                    raise TypeError('Unrecognised option "%s".' % entry)
            for entry, value in list(OPTION_DEFAULTS.items()):
                if entry not in options:
                    options[entry] = value
                keyword_value = _options[entry]
                if value != keyword_value:
                    options[entry] = keyword_value
        
        # XXXX this ignores an explicit list_values = True in combination
        # with _inspec. The user should *never* do that anyway, but still...
        if _inspec:
            options['list_values'] = False
        
        self._initialise(options)
        configspec = options['configspec']
        self._original_configspec = configspec
        self._load(infile, configspec)
        
        
    def _load(self, infile, configspec):
        if isinstance(infile, six.string_types):
            self.filename = infile
            if os.path.isfile(infile):
                with open(infile, 'rb') as h:
                    content = h.readlines() or []
            elif self.file_error:
                # raise an error if the file doesn't exist
                raise IOError('Config file not found: "%s".' % self.filename)
            else:
                # file doesn't already exist
                if self.create_empty:
                    # this is a good test that the filename specified
                    # isn't impossible - like on a non-existent device
                    with open(infile, 'w') as h:
                        h.write('')
                content = []
                
        elif isinstance(infile, (list, tuple)):
            content = list(infile)
            
        elif isinstance(infile, dict):
            # initialise self
            # the Section class handles creating subsections
            if isinstance(infile, ConfigObj):
                # get a copy of our ConfigObj
                def set_section(in_section, this_section):
                    for entry in in_section.scalars:
                        this_section[entry] = in_section[entry]
                    for section in in_section.sections:
                        this_section[section] = {}
                        set_section(in_section[section], this_section[section])
                set_section(infile, self)
                
            else:
                for entry in infile:
                    self[entry] = infile[entry]
            del self._errors
            
            if configspec is not None:
                self._handle_configspec(configspec)
            else:
                self.configspec = None
            return
        
        elif getattr(infile, 'read', MISSING) is not MISSING:
            # This supports file like objects
            content = infile.read() or []
            # needs splitting into lines - but needs doing *after* decoding
            # in case it's not an 8 bit encoding
        else:
            raise TypeError('infile must be a filename, file like object, or list of lines.')

        if content:
            # don't do it for the empty ConfigObj
            content = self._handle_bom(content)
            # infile is now *always* a list
            #
            # Set the newlines attribute (first line ending it finds)
            # and strip trailing '\n' or '\r' from lines
            for line in content:
                if (not line) or (line[-1] not in ('\r', '\n')):
                    continue
                for end in ('\r\n', '\n', '\r'):
                    if line.endswith(end):
                        self.newlines = end
                        break
                break

        assert all(isinstance(line, six.string_types) for line in content), repr(content)
        content = [line.rstrip('\r\n') for line in content]
            
        self._parse(content)
        # if we had any errors, now is the time to raise them
        if self._errors:
            info = "at line %s." % self._errors[0].line_number
            if len(self._errors) > 1:
                msg = "Parsing failed with several errors.\nFirst error %s" % info
                error = ConfigObjError(msg)
            else:
                error = self._errors[0]
            # set the errors attribute; it's a list of tuples:
            # (error_type, message, line_number)
            error.errors = self._errors
            # set the config attribute
            error.config = self
            raise error
        # delete private attributes
        del self._errors
        
        if configspec is None:
            self.configspec = None
        else:
            self._handle_configspec(configspec)
    
    
    def _initialise(self, options=None):
        if options is None:
            options = OPTION_DEFAULTS
            
        # initialise a few variables
        self.filename = None
        self._errors = []
        self.raise_errors = options['raise_errors']
        self.interpolation = options['interpolation']
        self.list_values = options['list_values']
        self.create_empty = options['create_empty']
        self.file_error = options['file_error']
        self.stringify = options['stringify']
        self.indent_type = options['indent_type']
        self.encoding = options['encoding']
        self.default_encoding = options['default_encoding']
        self.BOM = False
        self.newlines = None
        self.write_empty_values = options['write_empty_values']
        self.unrepr = options['unrepr']
        
        self.initial_comment = []
        self.final_comment = []
        self.configspec = None
        
        if self._inspec:
            self.list_values = False
        
        # Clear section attributes as well
        Section._initialise(self)
        
        
    def __repr__(self):
        def _getval(key):
            try:
                return self[key]
            except MissingInterpolationOption:
                return dict.__getitem__(self, key)
        return ('ConfigObj({%s})' % 
                ', '.join([('%s: %s' % (repr(key), repr(_getval(key)))) 
                for key in (self.scalars + self.sections)]))
    
    
    def _handle_bom(self, infile):
        """
        Handle any BOM, and decode if necessary.
        
        If an encoding is specified, that *must* be used - but the BOM should
        still be removed (and the BOM attribute set).
        
        (If the encoding is wrongly specified, then a BOM for an alternative
        encoding won't be discovered or removed.)
        
        If an encoding is not specified, UTF8 or UTF16 BOM will be detected and
        removed. The BOM attribute will be set. UTF16 will be decoded to
        unicode.
        
        NOTE: This method must not be called with an empty ``infile``.
        
        Specifying the *wrong* encoding is likely to cause a
        ``UnicodeDecodeError``.
        
        ``infile`` must always be returned as a list of lines, but may be
        passed in as a single string.
        """

        if ((self.encoding is not None) and
            (self.encoding.lower() not in BOM_LIST)):
            # No need to check for a BOM
            # the encoding specified doesn't have one
            # just decode
            return self._decode(infile, self.encoding)
        
        if isinstance(infile, (list, tuple)):
            line = infile[0]
        else:
            line = infile

        if isinstance(line, six.text_type):
            # it's already decoded and there's no need to do anything
            # else, just use the _decode utility method to handle
            # listifying appropriately
            return self._decode(infile, self.encoding)

        if self.encoding is not None:
            # encoding explicitly supplied
            # And it could have an associated BOM
            # TODO: if encoding is just UTF16 - we ought to check for both
            # TODO: big endian and little endian versions.
            enc = BOM_LIST[self.encoding.lower()]
            if enc == 'utf_16':
                # For UTF16 we try big endian and little endian
                for BOM, (encoding, final_encoding) in list(BOMS.items()):
                    if not final_encoding:
                        # skip UTF8
                        continue
                    if infile.startswith(BOM):
                        ### BOM discovered
                        ##self.BOM = True
                        # Don't need to remove BOM
                        return self._decode(infile, encoding)
                    
                # If we get this far, will *probably* raise a DecodeError
                # As it doesn't appear to start with a BOM
                return self._decode(infile, self.encoding)
            
            # Must be UTF8
            BOM = BOM_SET[enc]
            if not line.startswith(BOM):
                return self._decode(infile, self.encoding)
            
            newline = line[len(BOM):]
            
            # BOM removed
            if isinstance(infile, (list, tuple)):
                infile[0] = newline
            else:
                infile = newline
            self.BOM = True
            return self._decode(infile, self.encoding)
        
        # No encoding specified - so we need to check for UTF8/UTF16
        for BOM, (encoding, final_encoding) in list(BOMS.items()):
            if not isinstance(line, six.binary_type) or not line.startswith(BOM):
                # didn't specify a BOM, or it's not a bytestring
                continue
            else:
                # BOM discovered
                self.encoding = final_encoding
                if not final_encoding:
                    self.BOM = True
                    # UTF8
                    # remove BOM
                    newline = line[len(BOM):]
                    if isinstance(infile, (list, tuple)):
                        infile[0] = newline
                    else:
                        infile = newline
                    # UTF-8
                    if isinstance(infile, six.text_type):
                        return infile.splitlines(True)
                    elif isinstance(infile, six.binary_type):
                        return infile.decode('utf-8').splitlines(True)
                    else:
                        return self._decode(infile, 'utf-8')
                # UTF16 - have to decode
                return self._decode(infile, encoding)
            

        if six.PY2 and isinstance(line, str):
            # don't actually do any decoding, since we're on python 2 and
            # returning a bytestring is fine
            return self._decode(infile, None)
        # No BOM discovered and no encoding specified, default to UTF-8
        if isinstance(infile, six.binary_type):
            return infile.decode('utf-8').splitlines(True)
        else:
            return self._decode(infile, 'utf-8')


    def _a_to_u(self, aString):
        """Decode ASCII strings to unicode if a self.encoding is specified."""
        if isinstance(aString, six.binary_type) and self.encoding:
            return aString.decode(self.encoding)
        else:
            return aString


    def _decode(self, infile, encoding):
        """
        Decode infile to unicode. Using the specified encoding.
        
        if is a string, it also needs converting to a list.
        """
        if isinstance(infile, six.string_types):
            return infile.splitlines(True)
        if isinstance(infile, six.binary_type):
            # NOTE: Could raise a ``UnicodeDecodeError``
            if encoding:
                return infile.decode(encoding).splitlines(True)
            else:
                return infile.splitlines(True)

        if encoding:
            for i, line in enumerate(infile):
                if isinstance(line, six.binary_type):
                    # NOTE: The isinstance test here handles mixed lists of unicode/string
                    # NOTE: But the decode will break on any non-string values
                    # NOTE: Or could raise a ``UnicodeDecodeError``
                    infile[i] = line.decode(encoding)
        return infile


    def _decode_element(self, line):
        """Decode element to unicode if necessary."""
        if isinstance(line, six.binary_type) and self.default_encoding:
            return line.decode(self.default_encoding)
        else:
            return line


    # TODO: this may need to be modified
    def _str(self, value):
        """
        Used by ``stringify`` within validate, to turn non-string values
        into strings.
        """
        if not isinstance(value, six.string_types):
            # intentially 'str' because it's just whatever the "normal"
            # string type is for the python version we're dealing with
            return str(value)
        else:
            return value


    def _parse(self, infile):
        """Actually parse the config file."""
        temp_list_values = self.list_values
        if self.unrepr:
            self.list_values = False
            
        comment_list = []
        done_start = False
        this_section = self
        maxline = len(infile) - 1
        cur_index = -1
        reset_comment = False
        
        while cur_index < maxline:
            if reset_comment:
                comment_list = []
            cur_index += 1
            line = infile[cur_index]
            sline = line.strip()
            # do we have anything on the line ?
            if not sline or sline.startswith('#'):
                reset_comment = False
                comment_list.append(line)
                continue
            
            if not done_start:
                # preserve initial comment
                self.initial_comment = comment_list
                comment_list = []
                done_start = True
                
            reset_comment = True
            # first we check if it's a section marker
            mat = self._sectionmarker.match(line)
            if mat is not None:
                # is a section line
                (indent, sect_open, sect_name, sect_close, comment) = mat.groups()
                if indent and (self.indent_type is None):
                    self.indent_type = indent
                cur_depth = sect_open.count('[')
                if cur_depth != sect_close.count(']'):
                    self._handle_error("Cannot compute the section depth",
                                       NestingError, infile, cur_index)
                    continue
                
                if cur_depth < this_section.depth:
                    # the new section is dropping back to a previous level
                    try:
                        parent = self._match_depth(this_section,
                                                   cur_depth).parent
                    except SyntaxError:
                        self._handle_error("Cannot compute nesting level",
                                           NestingError, infile, cur_index)
                        continue
                elif cur_depth == this_section.depth:
                    # the new section is a sibling of the current section
                    parent = this_section.parent
                elif cur_depth == this_section.depth + 1:
                    # the new section is a child the current section
                    parent = this_section
                else:
                    self._handle_error("Section too nested",
                                       NestingError, infile, cur_index)
                    continue
                    
                sect_name = self._unquote(sect_name)
                if sect_name in parent:
                    self._handle_error('Duplicate section name',
                                       DuplicateError, infile, cur_index)
                    continue
                
                # create the new section
                this_section = Section(
                    parent,
                    cur_depth,
                    self,
                    name=sect_name)
                parent[sect_name] = this_section
                parent.inline_comments[sect_name] = comment
                parent.comments[sect_name] = comment_list
                continue
            #
            # it's not a section marker,
            # so it should be a valid ``key = value`` line
            mat = self._keyword.match(line)
            if mat is None:
                self._handle_error(
                    'Invalid line ({0!r}) (matched as neither section nor keyword)'.format(line),
                    ParseError, infile, cur_index)
            else:
                # is a keyword value
                # value will include any inline comment
                (indent, key, value) = mat.groups()
                if indent and (self.indent_type is None):
                    self.indent_type = indent
                # check for a multiline value
                if value[:3] in ['"""', "'''"]:
                    try:
                        value, comment, cur_index = self._multiline(
                            value, infile, cur_index, maxline)
                    except SyntaxError:
                        self._handle_error(
                            'Parse error in multiline value',
                            ParseError, infile, cur_index)
                        continue
                    else:
                        if self.unrepr:
                            comment = ''
                            try:
                                value = unrepr(value)
                            except Exception as e:
                                if type(e) == UnknownType:
                                    msg = 'Unknown name or type in value'
                                else:
                                    msg = 'Parse error from unrepr-ing multiline value'
                                self._handle_error(msg, UnreprError, infile,
                                    cur_index)
                                continue
                else:
                    if self.unrepr:
                        comment = ''
                        try:
                            value = unrepr(value)
                        except Exception as e:
                            if isinstance(e, UnknownType):
                                msg = 'Unknown name or type in value'
                            else:
                                msg = 'Parse error from unrepr-ing value'
                            self._handle_error(msg, UnreprError, infile,
                                cur_index)
                            continue
                    else:
                        # extract comment and lists
                        try:
                            (value, comment) = self._handle_value(value)
                        except SyntaxError:
                            self._handle_error(
                                'Parse error in value',
                                ParseError, infile, cur_index)
                            continue
                #
                key = self._unquote(key)
                if key in this_section:
                    self._handle_error(
                        'Duplicate keyword name',
                        DuplicateError, infile, cur_index)
                    continue
                # add the key.
                # we set unrepr because if we have got this far we will never
                # be creating a new section
                this_section.__setitem__(key, value, unrepr=True)
                this_section.inline_comments[key] = comment
                this_section.comments[key] = comment_list
                continue
        #
        if self.indent_type is None:
            # no indentation used, set the type accordingly
            self.indent_type = ''

        # preserve the final comment
        if not self and not self.initial_comment:
            self.initial_comment = comment_list
        elif not reset_comment:
            self.final_comment = comment_list
        self.list_values = temp_list_values


    def _match_depth(self, sect, depth):
        """
        Given a section and a depth level, walk back through the sections
        parents to see if the depth level matches a previous section.
        
        Return a reference to the right section,
        or raise a SyntaxError.
        """
        while depth < sect.depth:
            if sect is sect.parent:
                # we've reached the top level already
                raise SyntaxError()
            sect = sect.parent
        if sect.depth == depth:
            return sect
        # shouldn't get here
        raise SyntaxError()


    def _handle_error(self, text, ErrorClass, infile, cur_index):
        """
        Handle an error according to the error settings.
        
        Either raise the error or store it.
        The error will have occured at ``cur_index``
        """
        line = infile[cur_index]
        cur_index += 1
        message = '{0} at line {1}.'.format(text, cur_index)
        error = ErrorClass(message, cur_index, line)
        if self.raise_errors:
            # raise the error - parsing stops here
            raise error
        # store the error
        # reraise when parsing has finished
        self._errors.append(error)


    def _unquote(self, value):
        """Return an unquoted version of a value"""
        if not value:
            # should only happen during parsing of lists
            raise SyntaxError
        if (value[0] == value[-1]) and (value[0] in ('"', "'")):
            value = value[1:-1]
        return value


    def _quote(self, value, multiline=True):
        """
        Return a safely quoted version of a value.
        
        Raise a ConfigObjError if the value cannot be safely quoted.
        If multiline is ``True`` (default) then use triple quotes
        if necessary.
        
        * Don't quote values that don't need it.
        * Recursively quote members of a list and return a comma joined list.
        * Multiline is ``False`` for lists.
        * Obey list syntax for empty and single member lists.
        
        If ``list_values=False`` then the value is only quoted if it contains
        a ``\\n`` (is multiline) or '#'.
        
        If ``write_empty_values`` is set, and the value is an empty string, it
        won't be quoted.
        """
        if multiline and self.write_empty_values and value == '':
            # Only if multiline is set, so that it is used for values not
            # keys, and not values that are part of a list
            return ''
        
        if multiline and isinstance(value, (list, tuple)):
            if not value:
                return ','
            elif len(value) == 1:
                return self._quote(value[0], multiline=False) + ','
            return ', '.join([self._quote(val, multiline=False)
                for val in value])
        if not isinstance(value, six.string_types):
            if self.stringify:
                # intentially 'str' because it's just whatever the "normal"
                # string type is for the python version we're dealing with
                value = str(value)
            else:
                raise TypeError('Value "%s" is not a string.' % value)

        if not value:
            return '""'
        
        no_lists_no_quotes = not self.list_values and '\n' not in value and '#' not in value
        need_triple = multiline and ((("'" in value) and ('"' in value)) or ('\n' in value ))
        hash_triple_quote = multiline and not need_triple and ("'" in value) and ('"' in value) and ('#' in value)
        check_for_single = (no_lists_no_quotes or not need_triple) and not hash_triple_quote
        
        if check_for_single:
            if not self.list_values:
                # we don't quote if ``list_values=False``
                quot = noquot
            # for normal values either single or double quotes will do
            elif '\n' in value:
                # will only happen if multiline is off - e.g. '\n' in key
                raise ConfigObjError('Value "%s" cannot be safely quoted.' % value)
            elif ((value[0] not in wspace_plus) and
                    (value[-1] not in wspace_plus) and
                    (',' not in value)):
                quot = noquot
            else:
                quot = self._get_single_quote(value)
        else:
            # if value has '\n' or "'" *and* '"', it will need triple quotes
            quot = self._get_triple_quote(value)
        
        if quot == noquot and '#' in value and self.list_values:
            quot = self._get_single_quote(value)
                
        return quot % value
    
    
    def _get_single_quote(self, value):
        if ("'" in value) and ('"' in value):
            raise ConfigObjError('Value "%s" cannot be safely quoted.' % value)
        elif '"' in value:
            quot = squot
        else:
            quot = dquot
        return quot
    
    
    def _get_triple_quote(self, value):
        if (value.find('"""') != -1) and (value.find("'''") != -1):
            raise ConfigObjError('Value "%s" cannot be safely quoted.' % value)
        if value.find('"""') == -1:
            quot = tdquot
        else:
            quot = tsquot 
        return quot


    def _handle_value(self, value):
        """
        Given a value string, unquote, remove comment,
        handle lists. (including empty and single member lists)
        """
        if self._inspec:
            # Parsing a configspec so don't handle comments
            return (value, '')
        # do we look for lists in values ?
        if not self.list_values:
            mat = self._nolistvalue.match(value)
            if mat is None:
                raise SyntaxError()
            # NOTE: we don't unquote here
            return mat.groups()
        #
        mat = self._valueexp.match(value)
        if mat is None:
            # the value is badly constructed, probably badly quoted,
            # or an invalid list
            raise SyntaxError()
        (list_values, single, empty_list, comment) = mat.groups()
        if (list_values == '') and (single is None):
            # change this if you want to accept empty values
            raise SyntaxError()
        # NOTE: note there is no error handling from here if the regex
        # is wrong: then incorrect values will slip through
        if empty_list is not None:
            # the single comma - meaning an empty list
            return ([], comment)
        if single is not None:
            # handle empty values
            if list_values and not single:
                # FIXME: the '' is a workaround because our regex now matches
                #   '' at the end of a list if it has a trailing comma
                single = None
            else:
                single = single or '""'
                single = self._unquote(single)
        if list_values == '':
            # not a list value
            return (single, comment)
        the_list = self._listvalueexp.findall(list_values)
        the_list = [self._unquote(val) for val in the_list]
        if single is not None:
            the_list += [single]
        return (the_list, comment)


    def _multiline(self, value, infile, cur_index, maxline):
        """Extract the value, where we are in a multiline situation."""
        quot = value[:3]
        newvalue = value[3:]
        single_line = self._triple_quote[quot][0]
        multi_line = self._triple_quote[quot][1]
        mat = single_line.match(value)
        if mat is not None:
            retval = list(mat.groups())
            retval.append(cur_index)
            return retval
        elif newvalue.find(quot) != -1:
            # somehow the triple quote is missing
            raise SyntaxError()
        #
        while cur_index < maxline:
            cur_index += 1
            newvalue += '\n'
            line = infile[cur_index]
            if line.find(quot) == -1:
                newvalue += line
            else:
                # end of multiline, process it
                break
        else:
            # we've got to the end of the config, oops...
            raise SyntaxError()
        mat = multi_line.match(line)
        if mat is None:
            # a badly formed line
            raise SyntaxError()
        (value, comment) = mat.groups()
        return (newvalue + value, comment, cur_index)


    def _handle_configspec(self, configspec):
        """Parse the configspec."""
        # FIXME: Should we check that the configspec was created with the 
        #        correct settings ? (i.e. ``list_values=False``)
        if not isinstance(configspec, ConfigObj):
            try:
                configspec = ConfigObj(configspec,
                                       raise_errors=True,
                                       file_error=True,
                                       _inspec=True)
            except ConfigObjError as e:
                # FIXME: Should these errors have a reference
                #        to the already parsed ConfigObj ?
                raise ConfigspecError('Parsing configspec failed: %s' % e)
            except IOError as e:
                raise IOError('Reading configspec failed: %s' % e)
        
        self.configspec = configspec
            

        
    def _set_configspec(self, section, copy):
        """
        Called by validate. Handles setting the configspec on subsections
        including sections to be validated by __many__
        """
        configspec = section.configspec
        many = configspec.get('__many__')
        if isinstance(many, dict):
            for entry in section.sections:
                if entry not in configspec:
                    section[entry].configspec = many
                    
        for entry in configspec.sections:
            if entry == '__many__':
                continue
            if entry not in section:
                section[entry] = {}
                section[entry]._created = True
                if copy:
                    # copy comments
                    section.comments[entry] = configspec.comments.get(entry, [])
                    section.inline_comments[entry] = configspec.inline_comments.get(entry, '')
                
            # Could be a scalar when we expect a section
            if isinstance(section[entry], Section):
                section[entry].configspec = configspec[entry]
                        

    def _write_line(self, indent_string, entry, this_entry, comment):
        """Write an individual line, for the write method"""
        # NOTE: the calls to self._quote here handles non-StringType values.
        if not self.unrepr:
            val = self._decode_element(self._quote(this_entry))
        else:
            val = repr(this_entry)
        return '%s%s%s%s%s' % (indent_string,
                               self._decode_element(self._quote(entry, multiline=False)),
                               self._a_to_u(' = '),
                               val,
                               self._decode_element(comment))


    def _write_marker(self, indent_string, depth, entry, comment):
        """Write a section marker line"""
        return '%s%s%s%s%s' % (indent_string,
                               self._a_to_u('[' * depth),
                               self._quote(self._decode_element(entry), multiline=False),
                               self._a_to_u(']' * depth),
                               self._decode_element(comment))


    def _handle_comment(self, comment):
        """Deal with a comment."""
        if not comment:
            return ''
        start = self.indent_type
        if not comment.startswith('#'):
            start += self._a_to_u(' # ')
        return (start + comment)


    # Public methods

    def write(self, outfile=None, section=None):
        """
        Write the current ConfigObj as a file
        
        tekNico: FIXME: use StringIO instead of real files
        
        >>> filename = a.filename
        >>> a.filename = 'test.ini'
        >>> a.write()
        >>> a.filename = filename
        >>> a == ConfigObj('test.ini', raise_errors=True)
        1
        >>> import os
        >>> os.remove('test.ini')
        """
        if self.indent_type is None:
            # this can be true if initialised from a dictionary
            self.indent_type = DEFAULT_INDENT_TYPE
            
        out = []
        cs = self._a_to_u('#')
        csp = self._a_to_u('# ')
        if section is None:
            int_val = self.interpolation
            self.interpolation = False
            section = self
            for line in self.initial_comment:
                line = self._decode_element(line)
                stripped_line = line.strip()
                if stripped_line and not stripped_line.startswith(cs):
                    line = csp + line
                out.append(line)
                
        indent_string = self.indent_type * section.depth
        for entry in (section.scalars + section.sections):
            if entry in section.defaults:
                # don't write out default values
                continue
            for comment_line in section.comments[entry]:
                comment_line = self._decode_element(comment_line.lstrip())
                if comment_line and not comment_line.startswith(cs):
                    comment_line = csp + comment_line
                out.append(indent_string + comment_line)
            this_entry = section[entry]
            comment = self._handle_comment(section.inline_comments[entry])
            
            if isinstance(this_entry, Section):
                # a section
                out.append(self._write_marker(
                    indent_string,
                    this_entry.depth,
                    entry,
                    comment))
                out.extend(self.write(section=this_entry))
            else:
                out.append(self._write_line(
                    indent_string,
                    entry,
                    this_entry,
                    comment))
                
        if section is self:
            for line in self.final_comment:
                line = self._decode_element(line)
                stripped_line = line.strip()
                if stripped_line and not stripped_line.startswith(cs):
                    line = csp + line
                out.append(line)
            self.interpolation = int_val
            
        if section is not self:
            return out
        
        if (self.filename is None) and (outfile is None):
            # output a list of lines
            # might need to encode
            # NOTE: This will *screw* UTF16, each line will start with the BOM
            if self.encoding:
                out = [l.encode(self.encoding) for l in out]
            if (self.BOM and ((self.encoding is None) or
                (BOM_LIST.get(self.encoding.lower()) == 'utf_8'))):
                # Add the UTF8 BOM
                if not out:
                    out.append('')
                out[0] = BOM_UTF8 + out[0]
            return out
        
        # Turn the list to a string, joined with correct newlines
        newline = self.newlines or os.linesep
        if (getattr(outfile, 'mode', None) is not None and outfile.mode == 'w'
            and sys.platform == 'win32' and newline == '\r\n'):
            # Windows specific hack to avoid writing '\r\r\n'
            newline = '\n'
        output = self._a_to_u(newline).join(out)
        if not output.endswith(newline):
            output += newline

        if isinstance(output, six.binary_type):
            output_bytes = output
        else:
            output_bytes = output.encode(self.encoding or
                                         self.default_encoding or
                                         'ascii')

        if self.BOM and ((self.encoding is None) or match_utf8(self.encoding)):
            # Add the UTF8 BOM
            output_bytes = BOM_UTF8 + output_bytes

        if outfile is not None:
            outfile.write(output_bytes)
        else:
            with open(self.filename, 'wb') as h:
                h.write(output_bytes)

    def validate(self, validator, preserve_errors=False, copy=False,
                 section=None):
        """
        Test the ConfigObj against a configspec.
        
        It uses the ``validator`` object from *validate.py*.
        
        To run ``validate`` on the current ConfigObj, call: ::
        
            test = config.validate(validator)
        
        (Normally having previously passed in the configspec when the ConfigObj
        was created - you can dynamically assign a dictionary of checks to the
        ``configspec`` attribute of a section though).
        
        It returns ``True`` if everything passes, or a dictionary of
        pass/fails (True/False). If every member of a subsection passes, it
        will just have the value ``True``. (It also returns ``False`` if all
        members fail).
        
        In addition, it converts the values from strings to their native
        types if their checks pass (and ``stringify`` is set).
        
        If ``preserve_errors`` is ``True`` (``False`` is default) then instead
        of a marking a fail with a ``False``, it will preserve the actual
        exception object. This can contain info about the reason for failure.
        For example the ``VdtValueTooSmallError`` indicates that the value
        supplied was too small. If a value (or section) is missing it will
        still be marked as ``False``.
        
        You must have the validate module to use ``preserve_errors=True``.
        
        You can then use the ``flatten_errors`` function to turn your nested
        results dictionary into a flattened list of failures - useful for
        displaying meaningful error messages.
        """
        if section is None:
            if self.configspec is None:
                raise ValueError('No configspec supplied.')
            if preserve_errors:
                # We do this once to remove a top level dependency on the validate module
                # Which makes importing configobj faster
                from validate import VdtMissingValue
                self._vdtMissingValue = VdtMissingValue
                
            section = self

            if copy:
                section.initial_comment = section.configspec.initial_comment
                section.final_comment = section.configspec.final_comment
                section.encoding = section.configspec.encoding
                section.BOM = section.configspec.BOM
                section.newlines = section.configspec.newlines
                section.indent_type = section.configspec.indent_type
            
        #
        # section.default_values.clear() #??
        configspec = section.configspec
        self._set_configspec(section, copy)

        
        def validate_entry(entry, spec, val, missing, ret_true, ret_false):
            section.default_values.pop(entry, None)
                
            try:
                section.default_values[entry] = validator.get_default_value(configspec[entry])
            except (KeyError, AttributeError, validator.baseErrorClass):
                # No default, bad default or validator has no 'get_default_value'
                # (e.g. SimpleVal)
                pass
            
            try:
                check = validator.check(spec,
                                        val,
                                        missing=missing
                                        )
            except validator.baseErrorClass as e:
                if not preserve_errors or isinstance(e, self._vdtMissingValue):
                    out[entry] = False
                else:
                    # preserve the error
                    out[entry] = e
                    ret_false = False
                ret_true = False
            else:
                ret_false = False
                out[entry] = True
                if self.stringify or missing:
                    # if we are doing type conversion
                    # or the value is a supplied default
                    if not self.stringify:
                        if isinstance(check, (list, tuple)):
                            # preserve lists
                            check = [self._str(item) for item in check]
                        elif missing and check is None:
                            # convert the None from a default to a ''
                            check = ''
                        else:
                            check = self._str(check)
                    if (check != val) or missing:
                        section[entry] = check
                if not copy and missing and entry not in section.defaults:
                    section.defaults.append(entry)
            return ret_true, ret_false
        
        #
        out = {}
        ret_true = True
        ret_false = True
        
        unvalidated = [k for k in section.scalars if k not in configspec]
        incorrect_sections = [k for k in configspec.sections if k in section.scalars]        
        incorrect_scalars = [k for k in configspec.scalars if k in section.sections]
        
        for entry in configspec.scalars:
            if entry in ('__many__', '___many___'):
                # reserved names
                continue
            if (not entry in section.scalars) or (entry in section.defaults):
                # missing entries
                # or entries from defaults
                missing = True
                val = None
                if copy and entry not in section.scalars:
                    # copy comments
                    section.comments[entry] = (
                        configspec.comments.get(entry, []))
                    section.inline_comments[entry] = (
                        configspec.inline_comments.get(entry, ''))
                #
            else:
                missing = False
                val = section[entry]
            
            ret_true, ret_false = validate_entry(entry, configspec[entry], val, 
                                                 missing, ret_true, ret_false)
        
        many = None
        if '__many__' in configspec.scalars:
            many = configspec['__many__']
        elif '___many___' in configspec.scalars:
            many = configspec['___many___']
        
        if many is not None:
            for entry in unvalidated:
                val = section[entry]
                ret_true, ret_false = validate_entry(entry, many, val, False,
                                                     ret_true, ret_false)
            unvalidated = []

        for entry in incorrect_scalars:
            ret_true = False
            if not preserve_errors:
                out[entry] = False
            else:
                ret_false = False
                msg = 'Value %r was provided as a section' % entry
                out[entry] = validator.baseErrorClass(msg)
        for entry in incorrect_sections:
            ret_true = False
            if not preserve_errors:
                out[entry] = False
            else:
                ret_false = False
                msg = 'Section %r was provided as a single value' % entry
                out[entry] = validator.baseErrorClass(msg)
                
        # Missing sections will have been created as empty ones when the
        # configspec was read.
        for entry in section.sections:
            # FIXME: this means DEFAULT is not copied in copy mode
            if section is self and entry == 'DEFAULT':
                continue
            if section[entry].configspec is None:
                unvalidated.append(entry)
                continue
            if copy:
                section.comments[entry] = configspec.comments.get(entry, [])
                section.inline_comments[entry] = configspec.inline_comments.get(entry, '')
            check = self.validate(validator, preserve_errors=preserve_errors, copy=copy, section=section[entry])
            out[entry] = check
            if check == False:
                ret_true = False
            elif check == True:
                ret_false = False
            else:
                ret_true = False
        
        section.extra_values = unvalidated
        if preserve_errors and not section._created:
            # If the section wasn't created (i.e. it wasn't missing)
            # then we can't return False, we need to preserve errors
            ret_false = False
        #
        if ret_false and preserve_errors and out:
            # If we are preserving errors, but all
            # the failures are from missing sections / values
            # then we can return False. Otherwise there is a
            # real failure that we need to preserve.
            ret_false = not any(out.values())
        if ret_true:
            return True
        elif ret_false:
            return False
        return out


    def reset(self):
        """Clear ConfigObj instance and restore to 'freshly created' state."""
        self.clear()
        self._initialise()
        # FIXME: Should be done by '_initialise', but ConfigObj constructor (and reload)
        #        requires an empty dictionary
        self.configspec = None
        # Just to be sure ;-)
        self._original_configspec = None
        
        
    def reload(self):
        """
        Reload a ConfigObj from file.
        
        This method raises a ``ReloadError`` if the ConfigObj doesn't have
        a filename attribute pointing to a file.
        """
        if not isinstance(self.filename, six.string_types):
            raise ReloadError()

        filename = self.filename
        current_options = {}
        for entry in OPTION_DEFAULTS:
            if entry == 'configspec':
                continue
            current_options[entry] = getattr(self, entry)
            
        configspec = self._original_configspec
        current_options['configspec'] = configspec
            
        self.clear()
        self._initialise(current_options)
        self._load(filename, configspec)
        


class SimpleVal(object):
    """
    A simple validator.
    Can be used to check that all members expected are present.
    
    To use it, provide a configspec with all your members in (the value given
    will be ignored). Pass an instance of ``SimpleVal`` to the ``validate``
    method of your ``ConfigObj``. ``validate`` will return ``True`` if all
    members are present, or a dictionary with True/False meaning
    present/missing. (Whole missing sections will be replaced with ``False``)
    """
    
    def __init__(self):
        self.baseErrorClass = ConfigObjError
    
    def check(self, check, member, missing=False):
        """A dummy check method, always returns the value unchanged."""
        if missing:
            raise self.baseErrorClass()
        return member


def flatten_errors(cfg, res, levels=None, results=None):
    """
    An example function that will turn a nested dictionary of results
    (as returned by ``ConfigObj.validate``) into a flat list.
    
    ``cfg`` is the ConfigObj instance being checked, ``res`` is the results
    dictionary returned by ``validate``.
    
    (This is a recursive function, so you shouldn't use the ``levels`` or
    ``results`` arguments - they are used by the function.)
    
    Returns a list of keys that failed. Each member of the list is a tuple::
    
        ([list of sections...], key, result)
    
    If ``validate`` was called with ``preserve_errors=False`` (the default)
    then ``result`` will always be ``False``.

    *list of sections* is a flattened list of sections that the key was found
    in.
    
    If the section was missing (or a section was expected and a scalar provided
    - or vice-versa) then key will be ``None``.
    
    If the value (or section) was missing then ``result`` will be ``False``.
    
    If ``validate`` was called with ``preserve_errors=True`` and a value
    was present, but failed the check, then ``result`` will be the exception
    object returned. You can use this as a string that describes the failure.
    
    For example *The value "3" is of the wrong type*.
    """
    if levels is None:
        # first time called
        levels = []
        results = []
    if res == True:
        return sorted(results)
    if res == False or isinstance(res, Exception):
        results.append((levels[:], None, res))
        if levels:
            levels.pop()
        return sorted(results)
    for (key, val) in list(res.items()):
        if val == True:
            continue
        if isinstance(cfg.get(key), dict):
            # Go down one level
            levels.append(key)
            flatten_errors(cfg[key], val, levels, results)
            continue
        results.append((levels[:], key, val))
    #
    # Go up one level
    if levels:
        levels.pop()
    #
    return sorted(results)


def get_extra_values(conf, _prepend=()):
    """
    Find all the values and sections not in the configspec from a validated
    ConfigObj.
    
    ``get_extra_values`` returns a list of tuples where each tuple represents
    either an extra section, or an extra value.
    
    The tuples contain two values, a tuple representing the section the value 
    is in and the name of the extra values. For extra values in the top level
    section the first member will be an empty tuple. For values in the 'foo'
    section the first member will be ``('foo',)``. For members in the 'bar'
    subsection of the 'foo' section the first member will be ``('foo', 'bar')``.
    
    NOTE: If you call ``get_extra_values`` on a ConfigObj instance that hasn't
    been validated it will return an empty list.
    """
    out = []
    
    out.extend([(_prepend, name) for name in conf.extra_values])
    for name in conf.sections:
        if name not in conf.extra_values:
            out.extend(get_extra_values(conf[name], _prepend + (name,)))
    return out


"""*A programming language is a medium of expression.* - Paul Graham"""
