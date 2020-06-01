##############################################################################
#
# Copyright (c) 2005 Zope Foundation and Contributors.
# All Rights Reserved.
#
# This software is subject to the provisions of the Zope Public License,
# Version 2.1 (ZPL).  A copy of the ZPL should accompany this distribution.
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL EXPRESS OR IMPLIED
# WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND FITNESS
# FOR A PARTICULAR PURPOSE.
#
##############################################################################
"""Deprecation Support

This module provides utilities to ease the development of backward-compatible
code.
"""
__docformat__ = "reStructuredText"
import sys
import types
import warnings

str_and_sequence_types = (str if str is not bytes else basestring, list, tuple)

class ShowSwitch(object):
    """Simple stack-based switch."""

    def __init__(self):
        self.stack = []

    def on(self):
        self.stack.pop()

    def off(self):
        self.stack.append(False)

    def reset(self):
        self.stack = []

    def __call__(self):
        return self.stack == []

    def __repr__(self):
        return '<ShowSwitch %s>' %(self() and 'on' or 'off')


# This attribute can be used to temporarly deactivate deprecation
# warnings, so that backward-compatibility code can import other
# backward-compatiblity components without warnings being produced.
__show__ = ShowSwitch()

class Suppressor(object):

    def __enter__(self):
        __show__.off()

    def __exit__(self, *ignored):
        __show__.on()

ogetattr = object.__getattribute__
class DeprecationProxy(object):

    def __init__(self, module):
        self.__original_module = module
        self.__deprecated = {}

    def deprecate(self, names, message, cls=DeprecationWarning):
        """Deprecate the given names."""
        if not isinstance(names, (tuple, list)):
            names = (names,)
        for name in names:
            self.__deprecated[name] = (message, cls)

    def __getattribute__(self, name):
        if name == 'deprecate' or name.startswith('_DeprecationProxy__'):
            return ogetattr(self, name)

        if name == '__class__':
            return types.ModuleType

        if name in ogetattr(self, '_DeprecationProxy__deprecated'):
            if __show__():
                msg, cls = self.__deprecated[name]
                warnings.warn(name + ': ' + msg, cls, 2)

        return getattr(ogetattr(self, '_DeprecationProxy__original_module'),
                       name)

    def __setattr__(self, name, value):
        if name.startswith('_DeprecationProxy__'):
            return object.__setattr__(self, name, value)

        setattr(self.__original_module, name, value)

    def __delattr__(self, name):
        if name.startswith('_DeprecationProxy__'):
            return object.__delattr__(self, name)

        delattr(self.__original_module, name)

class DeprecatedModule(object):

    def __init__(self, module, msg, cls=DeprecationWarning):
        self.__original_module = module
        self.__msg = msg
        self.__cls = cls

    def __getattribute__(self, name):
        if name.startswith('_DeprecatedModule__'):
            return ogetattr(self, name)

        if name == '__class__':
            return types.ModuleType

        if __show__():
            warnings.warn(self.__msg, self.__cls, 2)

        return getattr(ogetattr(self, '_DeprecatedModule__original_module'),
                       name)

    def __setattr__(self, name, value):
        if name.startswith('_DeprecatedModule__'):
            return object.__setattr__(self, name, value)
        setattr(self.__original_module, name, value)

    def __delattr__(self, name):
        if name.startswith('_DeprecatedModule__'):
            return object.__delattr__(self, name)
        delattr(self.__original_module, name)

class DeprecatedGetProperty(object):

    def __init__(self, prop, message, cls=DeprecationWarning):
        self.message = message
        self.prop = prop
        self.cls = cls

    def __get__(self, inst, klass):
        if __show__():
            warnings.warn(self.message, self.cls, 2)
        return self.prop.__get__(inst, klass)

class DeprecatedGetSetProperty(DeprecatedGetProperty):

    def __set__(self, inst, prop):
        if __show__():
            warnings.warn(self.message, self.cls, 2)
        self.prop.__set__(inst, prop)

class DeprecatedGetSetDeleteProperty(DeprecatedGetSetProperty):

    def __delete__(self, inst):
        if __show__():
            warnings.warn(self.message, self.cls, 2)
        self.prop.__delete__(inst)

def DeprecatedMethod(method, message, cls=DeprecationWarning):

    def deprecated_method(*args, **kw):
        if __show__():
            warnings.warn(message, cls, 2)
        return method(*args, **kw)

    return deprecated_method

def deprecated(specifier, message, cls=DeprecationWarning):
    """Deprecate the given names."""

    # A string specifier (or list of strings) means we're called
    # top-level in a module and are to deprecate things inside this
    # module
    if isinstance(specifier, str_and_sequence_types):
        globals = sys._getframe(1).f_globals
        modname = globals['__name__']

        if not isinstance(sys.modules[modname], DeprecationProxy):
            sys.modules[modname] = DeprecationProxy(sys.modules[modname])
        sys.modules[modname].deprecate(specifier, message, cls)


    # Anything else can mean the specifier is a function/method,
    # module, or just an attribute of a class
    elif isinstance(specifier, types.FunctionType):
        return DeprecatedMethod(specifier, message, cls)
    elif isinstance(specifier, types.ModuleType):
        return DeprecatedModule(specifier, message, cls)
    else:
        prop = specifier
        if hasattr(prop, '__get__') and hasattr(prop, '__set__') and \
               hasattr(prop, '__delete__'):
            return DeprecatedGetSetDeleteProperty(prop, message, cls)
        elif hasattr(prop, '__get__') and hasattr(prop, '__set__'):
            return DeprecatedGetSetProperty(prop, message, cls)
        elif hasattr(prop, '__get__'):
            return DeprecatedGetProperty(prop, message, cls)

class deprecate(object):
    """Deprecation decorator"""

    def __init__(self, msg, cls=DeprecationWarning):
        self.msg = msg
        self.cls = cls

    def __call__(self, func):
        return DeprecatedMethod(func, self.msg, self.cls)

def moved(to_location, unsupported_in=None, cls=DeprecationWarning):
    old = sys._getframe(1).f_globals['__name__']
    message = '%s has moved to %s.' % (old, to_location)
    if unsupported_in:
        message += " Import of %s will become unsupported in %s" % (
            old, unsupported_in)

    warnings.warn(message, cls, 3)
    __import__(to_location)

    fromdict = sys.modules[to_location].__dict__
    tomod = sys.modules[old]
    tomod.__doc__ = message

    for name, v in fromdict.items():
        if name not in tomod.__dict__:
            setattr(tomod, name, v)
