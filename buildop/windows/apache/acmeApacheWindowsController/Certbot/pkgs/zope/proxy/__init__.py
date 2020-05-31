##############################################################################
#
# Copyright (c) 2003 Zope Foundation and Contributors.
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
"""More convenience functions for dealing with proxies.
"""
import operator
import os
import pickle
import sys

from zope.interface import moduleProvides
from zope.proxy.interfaces import IProxyIntrospection

moduleProvides(IProxyIntrospection)
__all__ = tuple(IProxyIntrospection)

def ProxyIterator(p):
    yield p
    while isProxy(p):
        p = getProxiedObject(p)
        yield p


_MARKER = object()

def _WrapperType_Lookup(type_, name):
    """
    Looks up information in class dictionaries in MRO
    order, ignoring the proxy type itself.

    Returns the first found object, or _MARKER
    """

    for base in type_.mro():
        if base is AbstractPyProxyBase:
            continue
        res = base.__dict__.get(name, _MARKER)
        if res is not _MARKER:
            return res
    return _MARKER

def _get_wrapped(self):
    """
    Helper method to access the wrapped object.
    """
    return super(AbstractPyProxyBase, self).__getattribute__('_wrapped')

class _EmptyInterfaceDescriptor(object):
    """A descriptor for the attributes used on the class by the
    Python implementation of `zope.interface`.

    When wrapping builtin types, these descriptors prevent the objects
    we find in the AbstractPyProxyBase from being used.
    """

    def __get__(self, inst, klass):
        raise AttributeError()

    def __set__(self, inst, value):
        raise TypeError()

    def __delete__(self, inst):
        pass

    def __iter__(self):
        return self

    def __next__(self):
        raise StopIteration()
    next = __next__

class _ProxyMetaclass(type):
    # The metaclass is applied after the class definition
    # for Py2/Py3 compatibility.
    __implemented__ = _EmptyInterfaceDescriptor()

class AbstractPyProxyBase(object):
    """
    A reference implementation that cannot be instantiated. Most users
    will want to use :class:`PyProxyBase`.

    This type is intended to be used in multiple-inheritance
    scenarios, where another super class already has defined
    ``__slots__``. In order to subclass both that class and this
    class, you must include the ``_wrapped`` value in your own
    ``__slots__`` definition (or else you will get the infamous
    TypeError: "multiple bases have instance lay-out conflicts")
    """
    __slots__ = ()

    def __new__(cls, value=None):
        # Some subclasses (zope.security.proxy) fail to pass the object
        inst = super(AbstractPyProxyBase, cls).__new__(cls)
        inst._wrapped = value
        return inst

    def __init__(self, obj):
        self._wrapped = obj

    def __call__(self, *args, **kw):
        return self._wrapped(*args, **kw)

    def __repr__(self):
        return repr(self._wrapped)

    def __str__(self):
        return str(self._wrapped)

    def __unicode__(self):
        return unicode(self._wrapped)

    def __reduce__(self): # pragma: no cover  (__reduce_ex__ prevents normal)
        raise pickle.PicklingError

    def __reduce_ex__(self, proto):
        raise pickle.PicklingError

    # Rich comparison protocol
    def __lt__(self, other):
        return self._wrapped < other

    def __le__(self, other):
        return self._wrapped <= other

    def __eq__(self, other):
        return self._wrapped == other

    def __ne__(self, other):
        return self._wrapped != other

    def __gt__(self, other):
        return self._wrapped > other

    def __ge__(self, other):
        return self._wrapped >= other

    def __nonzero__(self):
        return bool(self._wrapped)
    __bool__ = __nonzero__ # Python3 compat

    def __hash__(self):
        return hash(self._wrapped)

    # Attribute protocol
    def __getattribute__(self, name):
        # Try to avoid accessing the _wrapped value until we need to.
        # We don't know how subclasses may be storing it
        # (e.g., persistent subclasses)
        if name == '_wrapped':
            return _get_wrapped(self)

        if name in ('__class__', '__module__'):
            # __class__ and __module__ are special cased in the C
            # implementation, because we will always find them on the
            # type of this object if we are being subclassed
            return getattr(_get_wrapped(self), name)

        if name in ('__reduce__', '__reduce_ex__'):
            # These things we specifically override and no one
            # can stop us, not even a subclass
            return object.__getattribute__(self, name)

        # First, look for descriptors in this object's type
        type_self = type(self)
        descriptor = _WrapperType_Lookup(type_self, name)
        if descriptor is _MARKER:
            # Nothing in the class, go straight to the wrapped object
            return getattr(_get_wrapped(self), name)

        if hasattr(descriptor, '__get__'):
            if not hasattr(descriptor, '__set__'):
                # Non-data-descriptor: call through to the wrapped object
                # to see if it's there
                try:
                    return getattr(_get_wrapped(self), name)
                except AttributeError:
                    pass
            # Data-descriptor on this type. Call it
            return descriptor.__get__(self, type_self)
        return descriptor

    def __getattr__(self, name):
        return getattr(self._wrapped, name)

    def __setattr__(self, name, value):
        if name == '_wrapped':
            return super(AbstractPyProxyBase, self).__setattr__(name, value)

        # First, look for descriptors in this object's type
        type_self = type(self)
        descriptor = _WrapperType_Lookup(type_self, name)
        if descriptor is _MARKER or not hasattr(descriptor, '__set__'):
            # Nothing in the class that's a descriptor,
            # go straight to the wrapped object
            return setattr(self._wrapped, name, value)

        return object.__setattr__(self, name, value)

    def __delattr__(self, name):
        if name == '_wrapped':
            raise AttributeError()
        delattr(self._wrapped, name)

    # Container protocols

    def __len__(self):
        return len(self._wrapped)

    def __getslice__(self, start, stop):
        try:
            getslice = type(self._wrapped).__getslice__
        except AttributeError:
            return self.__getitem__(slice(start, stop))
        return getslice(self._wrapped, start, stop)

    def __getitem__(self, key):
        return self._wrapped[key]

    def __setslice__(self, start, stop, value):
        try:
            setslice = type(self._wrapped).__setslice__
        except AttributeError:
            return self.__setitem__(slice(start, stop), value)
        return setslice(self._wrapped, start, stop, value)

    def __setitem__(self, key, value):
        self._wrapped[key] = value

    def __delitem__(self, key):
        del self._wrapped[key]

    def __iter__(self):
        # This handles a custom __iter__ and generator support at the same time.
        return iter(self._wrapped)

    def next(self):
        # Called when we wrap an iterator itself.
        return self._wrapped.next()

    def __next__(self): # pragma: no cover Python3
        return self._wrapped.__next__()

    # Python 2.7 won't let the C wrapper support __reversed__ :(
    #def __reversed__(self):
    #    return reversed(self._wrapped)

    def __contains__(self, item):
        return item in self._wrapped

    # Numeric protocol:  unary operators
    def __neg__(self):
        return -self._wrapped

    def __pos__(self):
        return +self._wrapped

    def __abs__(self):
        return abs(self._wrapped)

    def __invert__(self):
        return ~self._wrapped

    # Numeric protocol:  unary conversions
    def __complex__(self):
        return complex(self._wrapped)

    def __int__(self):
        return int(self._wrapped)

    def __long__(self):
        return long(self._wrapped)

    def __float__(self):
        return float(self._wrapped)

    def __oct__(self):
        return oct(self._wrapped)

    def __hex__(self):
        return hex(self._wrapped)

    def __index__(self):
        return operator.index(self._wrapped)

    # Numeric protocol:  binary coercion
    def __coerce__(self, other):
        left, right = coerce(self._wrapped, other)
        if left == self._wrapped and type(left) is type(self._wrapped):
            left = self
        return left, right

    # Numeric protocol:  binary arithmetic operators
    def __add__(self, other):
        return self._wrapped + other

    def __sub__(self, other):
        return self._wrapped - other

    def __mul__(self, other):
        return self._wrapped * other

    def __floordiv__(self, other):
        return self._wrapped // other

    def __truediv__(self, other): # pragma: no cover
        # Only one of __truediv__ and __div__ is meaningful at any one time.
        return self._wrapped / other

    def __div__(self, other): # pragma: no cover
        # Only one of __truediv__ and __div__ is meaningful at any one time.
        return self._wrapped / other

    def __mod__(self, other):
        return self._wrapped % other

    def __divmod__(self, other):
        return divmod(self._wrapped, other)

    def __pow__(self, other, modulus=None):
        if modulus is None:
            return pow(self._wrapped, other)
        return pow(self._wrapped, other, modulus)

    def __radd__(self, other):
        return other + self._wrapped

    def __rsub__(self, other):
        return other - self._wrapped

    def __rmul__(self, other):
        return other * self._wrapped

    def __rfloordiv__(self, other):
        return other // self._wrapped

    def __rtruediv__(self, other): # pragma: no cover
        # Only one of __rtruediv__ and __rdiv__ is meaningful at any one time.
        return other / self._wrapped

    def __rdiv__(self, other): # pragma: no cover
        # Only one of __rtruediv__ and __rdiv__ is meaningful at any one time.
        return other / self._wrapped

    def __rmod__(self, other):
        return other % self._wrapped

    def __rdivmod__(self, other):
        return divmod(other, self._wrapped)

    def __rpow__(self, other, modulus=None):
        if modulus is None:
            return pow(other, self._wrapped)
        # We can't actually get here, because we can't lie about our type()
        return pow(other, self._wrapped, modulus) # pragma: no cover

    # Numeric protocol:  binary bitwise operators
    def __lshift__(self, other):
        return self._wrapped << other

    def __rshift__(self, other):
        return self._wrapped >> other

    def __and__(self, other):
        return self._wrapped & other

    def __xor__(self, other):
        return self._wrapped ^ other

    def __or__(self, other):
        return self._wrapped | other

    def __rlshift__(self, other):
        return other << self._wrapped

    def __rrshift__(self, other):
        return other >> self._wrapped

    def __rand__(self, other):
        return other & self._wrapped

    def __rxor__(self, other):
        return other ^ self._wrapped

    def __ror__(self, other):
        return other | self._wrapped

    # Numeric protocol:  binary in-place operators
    def __iadd__(self, other):
        self._wrapped += other
        return self

    def __isub__(self, other):
        self._wrapped -= other
        return self

    def __imul__(self, other):
        self._wrapped *= other
        return self

    def __idiv__(self, other): # pragma: no cover
        # Only one of __itruediv__ and __idiv__ is meaningful at any one time.
        self._wrapped /= other
        return self

    def __itruediv__(self, other): # pragma: no cover
        # Only one of __itruediv__ and __idiv__ is meaningful at any one time.
        self._wrapped /= other
        return self

    def __ifloordiv__(self, other):
        self._wrapped //= other
        return self

    def __imod__(self, other):
        self._wrapped %= other
        return self

    def __ilshift__(self, other):
        self._wrapped <<= other
        return self

    def __irshift__(self, other):
        self._wrapped >>= other
        return self

    def __iand__(self, other):
        self._wrapped &= other
        return self

    def __ixor__(self, other):
        self._wrapped ^= other
        return self

    def __ior__(self, other):
        self._wrapped |= other
        return self

    def __ipow__(self, other, modulus=None):
        if modulus is None:
            self._wrapped **= other
        else: # pragma: no cover
            # There is no syntax which triggers in-place pow w/ modulus
            self._wrapped = pow(self._wrapped, other, modulus)
        return self

AbstractPyProxyBase = _ProxyMetaclass(str('AbstractPyProxyBase'), (),
                                      dict(AbstractPyProxyBase.__dict__))

class PyProxyBase(AbstractPyProxyBase):
    """Reference implementation.
    """
    __slots__ = ('_wrapped', )


def py_getProxiedObject(obj):
    if isinstance(obj, PyProxyBase):
        return obj._wrapped
    return obj

def py_setProxiedObject(obj, new_value):
    if not isinstance(obj, PyProxyBase):
        raise TypeError('Not a proxy')
    old, obj._wrapped = obj._wrapped, new_value
    return old

def py_isProxy(obj, klass=None):
    if klass is None:
        klass = PyProxyBase
    return isinstance(obj, klass)

def py_sameProxiedObjects(lhs, rhs):
    while isinstance(lhs, PyProxyBase):
        lhs = super(PyProxyBase, lhs).__getattribute__('_wrapped')
    while isinstance(rhs, PyProxyBase):
        rhs = super(PyProxyBase, rhs).__getattribute__('_wrapped')
    return lhs is rhs

def py_queryProxy(obj, klass=None, default=None):
    if klass is None:
        klass = PyProxyBase
    while obj is not None and not isinstance(obj, klass):
        obj = getattr(obj, '_wrapped', None)
    if obj is not None:
        return obj
    return default

def py_queryInnerProxy(obj, klass=None, default=None):
    if klass is None:
        klass = PyProxyBase
    found = []
    while obj is not None:
        if isinstance(obj, klass):
            found.append(obj) # stack
        obj = getattr(obj, '_wrapped', None)
    if found:
        return found[-1]
    return default

def py_removeAllProxies(obj):
    while isinstance(obj, PyProxyBase):
        obj = super(PyProxyBase, obj).__getattribute__('_wrapped')
    return obj

_c_available = False
if 'PURE_PYTHON' not in os.environ:
    try:
        from zope.proxy._zope_proxy_proxy import ProxyBase as _c_available
    except ImportError: # pragma: no cover
        pass

class PyNonOverridable(object):
    "Deprecated, only for BWC."
    def __init__(self, method_desc): # pragma: no cover PyPy
        self.desc = method_desc

if _c_available:
    # Python API:  not used in this module
    from zope.proxy._zope_proxy_proxy import ProxyBase
    from zope.proxy._zope_proxy_proxy import getProxiedObject
    from zope.proxy._zope_proxy_proxy import setProxiedObject
    from zope.proxy._zope_proxy_proxy import isProxy
    from zope.proxy._zope_proxy_proxy import sameProxiedObjects
    from zope.proxy._zope_proxy_proxy import queryProxy
    from zope.proxy._zope_proxy_proxy import queryInnerProxy
    from zope.proxy._zope_proxy_proxy import removeAllProxies

    # API for proxy-using C extensions.
    from zope.proxy._zope_proxy_proxy import _CAPI

else: # pragma: no cover
    # no C extension available, fall back
    ProxyBase = PyProxyBase
    getProxiedObject = py_getProxiedObject
    setProxiedObject = py_setProxiedObject
    isProxy = py_isProxy
    sameProxiedObjects = py_sameProxiedObjects
    queryProxy = py_queryProxy
    queryInnerProxy = py_queryInnerProxy
    removeAllProxies = py_removeAllProxies

def non_overridable(func):
    return property(lambda self: func.__get__(self))
