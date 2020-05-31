##############################################################################
#
# Copyright (c) 2006 Zope Foundation and Contributors.
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
"""Modules with defered attributes
"""
import sys
import warnings
import zope.proxy


class Deferred(object):

    def __init__(self, name, specifier):
        self.__name__ = name
        self.specifier = specifier

    _import_chicken = {}, {}, ['*']

    def get(self):

        specifier = self.specifier
        if ':' in specifier:
            module, name = specifier.split(':')
        else:
            module, name = specifier, ''

        v = __import__(module, *self._import_chicken)
        if name:
            for n in name.split('.'):
                v = getattr(v, n)
        return v

class DeferredAndDeprecated(Deferred):

    def __init__(self, name, specifier, message):
        super(DeferredAndDeprecated, self).__init__(name, specifier)
        self.message = message

    def get(self):
        warnings.warn(
            self.__name__ + " is deprecated. " + self.message,
            DeprecationWarning, stacklevel=3)

        return super(DeferredAndDeprecated, self).get()


class ModuleProxy(zope.proxy.ProxyBase):
    __slots__ = ('__deferred_definitions__', '__doc__')

    def __init__(self, module):
        super(ModuleProxy, self).__init__(module)
        self.__deferred_definitions__ = {}
        self.__doc__ = module.__doc__

    def __getattr__(self, name):
        try:
            get = self.__deferred_definitions__[name]
        except KeyError:
            raise AttributeError(name)
        v = get.get()
        setattr(self, name, v)
        try:
            del self.__deferred_definitions__[name]
        except KeyError:  # pragma: no cover
            pass
        return v

def initialize(level=1):
    """Prepare a module to support deferred imports.

    Modules do not need to call this directly, because the
    `define*` and `deprecated*` functions call it.

    This is intended to be called from the module to be prepared.
    The implementation wraps a proxy around the module and replaces
    the entry in sys.modules with the proxy.  It does no harm to
    call this function more than once for a given module, because
    this function does not re-wrap a proxied module.

    The level parameter specifies a relative stack depth.
    When this function is called directly by the module, level should be 1.
    When this function is called by a helper function, level should
    increase with the depth of the stack.

    Returns nothing when level is 1; otherwise returns the proxied module.
    """
    __name__ = sys._getframe(level).f_globals['__name__']
    module = sys.modules[__name__]
    if type(module) is not ModuleProxy:
        module = ModuleProxy(module)
        sys.modules[__name__] = module

    if level == 1:
        return
    return module

def define(**names):
    """Define deferred imports using keyword parameters.

    Each parameter specifies the importable name and how to import it.
    Use `module:name` syntax to import a name from a module, or `module`
    (no colon) to import a module.
    """
    module = initialize(2)
    __deferred_definitions__ = module.__deferred_definitions__
    for name, specifier in names.items():
        __deferred_definitions__[name] = Deferred(name, specifier)

def defineFrom(from_name, *names):
    """Define deferred imports from a particular module.

    The from_name specifies which module to import.
    The rest of the parameters specify names to import from that module.
    """
    module = initialize(2)
    __deferred_definitions__ = module.__deferred_definitions__
    for name in names:
        specifier = from_name + ':' + name
        __deferred_definitions__[name] = Deferred(name, specifier)

def deprecated(message, **names):
    """Define deferred and deprecated imports using keyword parameters.

    The first use of each name will generate a deprecation warning with
    the given message.

    Each parameter specifies the importable name and how to import it.
    Use `module:name` syntax to import a name from a module, or `module`
    (no colon) to import a module.
    """
    module = initialize(2)
    __deferred_definitions__ = module.__deferred_definitions__
    for name, specifier in names.items():
        __deferred_definitions__[name] = DeferredAndDeprecated(
            name, specifier, message)

def deprecatedFrom(message, from_name, *names):
    """Define deferred and deprecated imports from a particular module.

    The first use of each name will generate a deprecation warning with
    the given message.

    The from_name specifies which module to import.
    The rest of the parameters specify names to import from that module.
    """
    module = initialize(2)
    __deferred_definitions__ = module.__deferred_definitions__
    for name in names:
        specifier = from_name + ':' + name
        __deferred_definitions__[name] = DeferredAndDeprecated(
            name, specifier, message)
