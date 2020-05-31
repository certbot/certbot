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
"""Test base proxy class.
"""
import unittest

try:
    import zope.security
except ImportError: # pragma: no cover
    _HAVE_ZOPE_SECURITY = False
else:
    _HAVE_ZOPE_SECURITY = True

from zope.proxy._compat import PY3

class ModuleConformanceCase(unittest.TestCase):

    def test_module_conforms_to_IProxyIntrospection(self):
        from zope.interface.verify import verifyObject
        import zope.proxy
        from zope.proxy.interfaces import IProxyIntrospection
        verifyObject(IProxyIntrospection, zope.proxy)


class PyProxyBaseTestCase(unittest.TestCase):

    # Names of special methods
    getslice = '__getitem__' if PY3 else '__getslice__'
    setslice = '__setitem__' if PY3 else '__setslice__'


    def _getTargetClass(self):
        from zope.proxy import PyProxyBase
        return PyProxyBase

    def _makeOne(self, o):
        return self._getTargetClass()(o)

    def test_constructor(self):
        o = object()
        self.assertRaises(TypeError, self._makeOne, o, o)
        self.assertRaises(TypeError, self._makeOne, o, key='value')
        self.assertRaises(TypeError, self._makeOne, key='value')

    def test_subclass_constructor(self):
        class MyProxy(self._getTargetClass()):
            def __new__(cls, *args, **kwds):
                return super(MyProxy, cls).__new__(cls, *args, **kwds)
            def __init__(self, *args, **kwds):
                super(MyProxy, self).__init__(*args, **kwds)
        o1 = object()
        o2 = object()
        o = MyProxy((o1, o2))

        self.assertEqual(o1, o[0])
        self.assertEqual(o2, o[1])

        self.assertRaises(TypeError, MyProxy, o1, o2)
        self.assertRaises(TypeError, MyProxy, o1, key='value')
        self.assertRaises(TypeError, MyProxy, key='value')

        # Check that are passed to __init__() overrides what's passed
        # to __new__().
        class MyProxy2(self._getTargetClass()):
            def __new__(cls, *args, **kwds):
                return super(MyProxy2, cls).__new__(cls, 'value')

        proxy = MyProxy2('splat!')
        self.assertEqual(list(proxy), list('splat!'))

        class MyProxy3(MyProxy2):
            def __init__(self, arg):
                if list(self) != list('value'):
                    raise AssertionError("list(self) != list('value')")
                super(MyProxy3, self).__init__('another')

        proxy = MyProxy3('notused')
        self.assertEqual(list(proxy), list('another'))

    def test_custom_int_to_int(self):
        class CustomClass(object):
            def __int__(self):
                return 42
        proxy = self._makeOne(CustomClass())
        self.assertEqual(42, int(proxy))

    def test_string_to_float(self):
        proxy = self._makeOne("14")
        self.assertEqual(float("14"), float(proxy))

    def test_incorrect_string_to_int(self):
        proxy = self._makeOne("")
        self.assertRaises(ValueError, int, proxy)

    def test_incorrect_string_to_float(self):
        proxy = self._makeOne("")
        self.assertRaises(ValueError, float, proxy)

    def test_custom_float_to_float(self):
        class CustomClass(object):
            def __float__(self):
                return 42.0
        proxy = self._makeOne(CustomClass())
        self.assertEqual(42.0, float(proxy))

    @unittest.skipIf(PY3, "Gone in Py3")
    def test___unicode__of_unicode(self):
        s = u'Hello, \u2603'
        proxy = self._makeOne(s)
        self.assertEqual(unicode(proxy), s)

    @unittest.skipIf(PY3, "Gone in Py3")
    def test___unicode__of_custom_class(self):
        class CustomClass(object):
            def __unicode__(self):
                return u'Hello, \u2603'
        cc = CustomClass()
        self.assertEqual(unicode(cc), u'Hello, \u2603')
        proxy = self._makeOne(cc)
        self.assertEqual(unicode(proxy), u'Hello, \u2603')

    @unittest.skipIf(PY3, "Gone in Py3")
    def test___unicode__of_custom_class_no_unicode(self):
        class CustomClass(object):
            pass
        cc = CustomClass()
        cc_unicode = unicode(cc)
        self.assertEqual(type(cc_unicode), unicode)
        proxy = self._makeOne(cc)
        self.assertEqual(unicode(proxy), cc_unicode)

    def test___call__(self):
        def _foo():
            return 'FOO'
        proxy = self._makeOne(_foo)
        self.assertEqual(proxy(), 'FOO')

    @unittest.skipIf(PY3, "Gone in Py3")
    def test_callable(self):
        w = self._makeOne({}.get)
        self.assertTrue(callable(w))

    def test___repr__(self):
        def _foo():
            raise AssertionError("Not called")
        proxy = self._makeOne(_foo)
        self.assertEqual(repr(proxy), repr(_foo))

    def test___str__(self):
        def _foo():
            raise AssertionError("Not called")
        proxy = self._makeOne(_foo)
        self.assertEqual(str(proxy), str(_foo))

    @unittest.skipIf(PY3, "Gone in Py3")
    def test___unicode__(self):
        def _foo():
            raise AssertionError("Not called")
        proxy = self._makeOne(_foo)
        self.assertTrue(unicode(proxy).startswith('<function _foo'))

    @unittest.skipIf(PY3, "No old-style classes in Python 3")
    def test___reduce___via_pickling(self):
        import pickle

        # Proxies of old-style classes can't be pickled.
        class Thing:
            """This class is expected to be a classic class."""
        w = self._makeOne(Thing())
        self.assertRaises(pickle.PicklingError,
                          pickle.dumps, w)

    def test___eq___and___ne__(self):
        w = self._makeOne('foo')
        self.assertEqual(w, 'foo')

        o1 = Comparable(1)
        o2 = Comparable(1.0)
        o3 = Comparable("splat!")

        w1 = self._makeOne(o1)
        w2 = self._makeOne(o2)
        w3 = self._makeOne(o3)

        self.assertTrue(o1 == w1)
        self.assertTrue(o1 == w2)
        self.assertTrue(o2 == w1)
        self.assertTrue(w1 == o2)
        self.assertTrue(w2 == o1)

        self.assertTrue(o3 != w1)
        self.assertTrue(w1 != o3)
        self.assertTrue(w3 != o1)
        self.assertTrue(o1 != w3)

    def test___lt___and___le__(self):
        o1 = Comparable(1)
        o2 = Comparable(2.0)

        w1 = self._makeOne(o1)
        w2 = self._makeOne(o2)

        self.assertTrue(w1 < w2)
        self.assertTrue(w1 <= w2)
        self.assertTrue(o1 < w2)
        self.assertTrue(o1 <= w2)
        self.assertTrue(w1 < o2)
        self.assertTrue(w2 <= o2)

    def test___gt___and___ge__(self):
        o1 = Comparable(1)
        o2 = Comparable(2.0)

        w1 = self._makeOne(o1)
        w2 = self._makeOne(o2)

        self.assertTrue(w2 > w1)
        self.assertTrue(w2 >= w1)
        self.assertTrue(w2 > o1)
        self.assertTrue(w2 >= o1)
        self.assertTrue(o2 > w1)
        self.assertTrue(o2 >= w2)

    def test___nonzero__(self):
        w = self._makeOne(None)
        self.assertFalse(w)
        self.assertTrue(not w)

    def test___hash__(self):
        w1 = self._makeOne(1)
        self.assertEqual(hash(w1), hash(1))

    def test___getattr__miss_both(self):
        class Foo(object):
            pass
        o = Foo()
        w = self._makeOne(o)
        def _try():
            return w.nonesuch
        self.assertRaises(AttributeError, _try)

    def test___getattr__delegates_to_wrapped(self):
        class Foo(object):
            pass
        o = Foo()
        o.foo = 1
        w = self._makeOne(o)
        self.assertEqual(w.foo, 1)

    def test___getattr__delegates_to_wrapped_when_conflict(self):
        class Proxy(self._getTargetClass()):
            def foo(self):
                raise AssertionError("Not called")
        class Foo(object):
            def foo(self):
                return 'FOO'
        o = Foo()
        w = Proxy(o)
        self.assertEqual(w.foo(), 'FOO')

    def test___setattr__delegates_to_wrapped(self):
        class Foo(object):
            pass
        o = Foo()
        w = self._makeOne(o)
        w.foo = 1
        self.assertEqual(o.foo, 1)

    def test___setattr__sets_proxy_property(self):
        class Proxy(self._getTargetClass()):
            bar = property(
                lambda s: s.__dict__.get('_bar'),
                lambda s, v: s.__dict__.__setitem__('_bar', v)
                )
        class Foo(object):
            pass
        o = Foo()
        w = Proxy(o)
        w.bar = 43
        self.assertEqual(w.bar, 43)
        self.assertRaises(AttributeError, getattr, o, 'bar')

    def test___delattr___wrapped(self):
        class Foo(object):
            pass
        o = Foo()
        o.foo = 1
        w = self._makeOne(o)
        def _try():
            del w._wrapped
        self.assertRaises(AttributeError, _try)

    def test___delattr__delegates_to_wrapped(self):
        class Foo(object):
            pass
        o = Foo()
        o.foo = 1
        w = self._makeOne(o)
        del w.foo
        self.assertFalse('foo' in o.__dict__)

    def test___len__(self):
        l = []
        w = self._makeOne(l)
        self.assertEqual(len(w), 0)
        l.append(0)
        self.assertEqual(len(w), 1)

    def test___getitem_____setitem_____delitem__(self):
        w = self._makeOne({})
        self.assertRaises(KeyError, lambda: w[1])
        w[1] = 'a'
        self.assertEqual(w[1], 'a')
        del w[1]
        self.assertRaises(KeyError, lambda: w[1])
        def del_w_1():
            del w[1]
        self.assertRaises(KeyError, del_w_1)

    def test___getitem__w_slice_against_list(self):
        # Lists have special slicing behavior.
        pList = self._makeOne([1, 2])
        self.assertEqual(pList[-1:], [2])
        self.assertEqual(pList[-2:], [1, 2])
        self.assertEqual(pList[-3:], [1, 2])

    def test___getitem__w_slice_against_tuple(self):
        # Tuples also have special slicing behavior.
        pTuple = self._makeOne((1, 2))
        self.assertEqual(pTuple[-1:], (2,))
        self.assertEqual(pTuple[-2:], (1, 2))
        self.assertEqual(pTuple[-3:], (1, 2))

    def test___getitem__w_slice_against_derived_list(self):
        data = [1, 2]
        class DerivedList(list):
            def __getslice__(self, start, stop):
                return list.__getslice__(self, start, stop)

        pList = self._makeOne(DerivedList(data))

        self.assertEqual(pList[-1:], data[-1:])
        self.assertEqual(pList[-2:], data[-2:])
        self.assertEqual(pList[-3:], data[-3:])

    def test___getitem__w_slice_against_class_w_custom___getslice__(self):
        import sys
        test = self
        class Slicer(object):
            def __len__(self):
                return 2

            def __getslice__(self, start, end):
                return (start, end)

            def __getitem__(self, a_slice): # pragma: no cover
                test.assertTrue(PY3)
                # On Python 3, we basically just return what the test expects.
                # Mostly that's the computed indices (yay!) but there are
                # a few special cases.
                indices = a_slice.indices(len(self))
                return (indices[0] if a_slice.start != -3 else -1,
                        indices[-1] if a_slice.stop is not None else sys.maxsize)

        pSlicer = self._makeOne(Slicer())
        self.assertEqual(pSlicer[:1][0], 0)
        self.assertEqual(pSlicer[:1][1], 1)
        self.assertEqual(pSlicer[:-1][0], 0)
        self.assertEqual(pSlicer[:-1][1], 1)
        self.assertEqual(pSlicer[-1:][0], 1)
        self.assertEqual(pSlicer[-2:][0], 0)
        self.assertEqual(pSlicer[-3:], (-1, sys.maxsize))

    def test___getslice___dne_uses_getitem(self):
        class Missing(Exception):
            pass
        class Get(object):
            def __getitem__(self, x):
                raise Missing('__getitem__')

        target = Get()
        proxy = self._makeOne(target)
        with self.assertRaisesRegexp(Missing,
                                     '__getitem__'):
            proxy[1:2]

    def test___getslice___error_propagates(self):
        test = self
        class Missing(Exception):
            pass
        class Get(object):
            def __getitem__(self, x): # pragma: no cover (only py3)
                test.assertTrue(PY3)
                raise Missing('__getitem__')
            def __getslice__(self, start, stop):
                raise Missing("__getslice__")
        target = Get()
        proxy = self._makeOne(target)
        with self.assertRaisesRegexp(Missing,
                                     self.getslice):
            proxy[1:2]

    def test___setslice___against_list(self):
        # Lists have special slicing bahvior for assignment as well.
        pList = self._makeOne([1, 2])
        pList[-1:] = [3, 4]
        self.assertEqual(pList, [1, 3, 4])
        pList = self._makeOne([1, 2])
        pList[-2:] = [3, 4]
        self.assertEqual(pList, [3, 4])
        pList = self._makeOne([1, 2])
        pList[-3:] = [3, 4]
        self.assertEqual(pList, [3, 4])

    def test___setslice___against_derived_list(self):
        # This behavior should be true for all list-derived classes.
        class DerivedList(list):
            pass

        pList = self._makeOne(DerivedList([1, 2]))
        pList[-1:] = [3, 4]
        self.assertEqual(pList, [1, 3, 4])
        pList = self._makeOne(DerivedList([1, 2]))
        pList[-2:] = [3, 4]
        self.assertEqual(pList, [3, 4])
        pList = self._makeOne(DerivedList([1, 2]))
        pList[-3:] = [3, 4]
        self.assertEqual(pList, [3, 4])

    def test___setslice___error_propagates(self):
        class Missing(Exception):
            pass
        class Set(object):
            def __setitem__(self, k, v):
                raise Missing('__setitem__') # pragma: no cover (only py3)
            def __setslice__(self, start, stop, value):
                raise Missing("__setslice__")
        target = Set()
        proxy = self._makeOne(target)
        with self.assertRaisesRegexp(Missing,
                                     self.setslice):
            proxy[1:2] = 1

    def test___setslice___dne_uses_setitem(self):
        class Missing(Exception):
            pass
        class Set(object):
            def __setitem__(self, k, v):
                raise Missing('__setitem__')

        target = Set()
        proxy = self._makeOne(target)
        with self.assertRaisesRegexp(Missing,
                                     '__setitem__'):
            proxy[1:2] = 1


    def test___iter___w_wrapped_iterable(self):
        a = [1, 2, 3]
        b = []
        for x in self._makeOne(a):
            b.append(x)
        self.assertEqual(a, b)

    def test___iter___w_wrapped_iterator(self):
        # Wrap an iterator before starting iteration.
        # PyObject_GetIter() will still be called on the proxy.
        a = [1, 2, 3]
        b = []
        for x in self._makeOne(iter(a)):
            b.append(x)
        self.assertEqual(a, b)
        t = tuple(self._makeOne(iter(a)))
        self.assertEqual(t, (1, 2, 3))

    def test___iter___returns_self_if_defined(self):
        # Return the wrapped object itself, if it is an iterator.
        class MyIter(object):
            def __iter__(self):
                return self
            def __next__(self):
                raise AssertionError("Not called")
            next = __next__
        myIter = MyIter()
        p = self._makeOne(myIter)
        self.assertEqual(iter(p), p)
        self.assertTrue(isinstance(iter(p), MyIter))

    def test___iter___next_when_returned_by_iterable(self):
        # Wrap an iterator within the iteration protocol, expecting it
        # still to work.  PyObject_GetIter() will not be called on the
        # proxy, so the tp_iter slot won't unwrap it.

        class Iterable(object):
            def __init__(self, test, data):
                self.test = test
                self.data = data
            def __iter__(self):
                return self.test._makeOne(iter(self.data))

        a = [1, 2, 3]
        b = []
        for x in Iterable(self, a):
            b.append(x)
        self.assertEqual(a, b)

    # Python 2.7 won't let the C wrapper support __reversed__ :(
    #def test___reversed__(self):
    #    w = self._makeOne([0, 1, 2, 3])
    #    self.assertEqual(list(reversed(w)), [3, 2, 1, 0])

    def test___contains__(self):
        w = self._makeOne([0, 1, 2, 3])
        self.assertTrue(1 in w)
        self.assertFalse(4 in w)

    def test___index__(self):
        import operator
        w = self._makeOne(42)
        self.assertEqual(operator.index(w), 42)

    # Numeric ops.

    @property
    def unops(self):
        ops = [
            "-x",
            "+x",
            "abs(x)",
            "~x",
            "int(x)",
            "float(x)",
            "complex(x)",
        ]
        if not PY3: # long is gone in Python 3
            ops.append("long(x)")
        return ops

    def test_unops(self):
        for expr in self.unops:
            x = 1
            y = eval(expr)
            x = self._makeOne(1)
            z = eval(expr)
            self.assertEqual(z, y,
                             "x=%r; expr=%r" % (x, expr))

    def test_odd_unops(self):
        # unops that don't return a proxy
        funcs = (lambda x: not x,)
        if not PY3:
            funcs += (oct, hex)
        for func in funcs:
            self.assertEqual(func(self._makeOne(100)), func(100))

    binops = [
        "x+y", "x-y", "x*y", "x/y", "x//y", "x%y", "divmod(x, y)",
        "x**y", #"pow(x,y,3)" (RHS coercion not supported w/ modulus)
        "x<<y", "x>>y", "x&y", "x|y", "x^y",
        ]

    def test_binops(self):
        for expr in self.binops:
            first = 1
            for x in [1, self._makeOne(1)]:
                for y in [2, self._makeOne(2)]:
                    if first:
                        z = eval(expr)
                        first = 0
                    else:
                        self.assertEqual(eval(expr), z,
                                         "x=%r; y=%r; expr=%r" % (x, y, expr))

    def test_pow_w_modulus(self):
        x = self._makeOne(2)
        # Can't coerce 2nd / 3rd args in pure Python, because we can't
        # lie about our type
        self.assertEqual(pow(x, 3, 3), 2)

    def test_inplace(self):
        # TODO: should test all inplace operators...
        pa = self._makeOne(1)
        pa += 2
        self.assertEqual(pa, 3)

        a = [1, 2, 3]
        pa = qa = self._makeOne(a)
        pa += [4, 5, 6]
        self.assertTrue(pa is qa)
        self.assertEqual(a, [1, 2, 3, 4, 5, 6])

        pa = self._makeOne(2)
        pa -= 1
        self.assertEqual(pa, 1)
        pa *= 4
        self.assertEqual(pa, 4)
        pa /= 2
        self.assertEqual(pa, 2)
        pa //= 2
        self.assertEqual(pa, 1)
        pa += 2
        self.assertEqual(pa, 3)
        pa %= 2
        self.assertEqual(pa, 1)

        pa = self._makeOne(2)
        pa **= 2
        self.assertEqual(pa, 4)
        pa <<= 1
        self.assertEqual(pa, 8)
        pa >>= 2
        self.assertEqual(pa, 2)

        pa = self._makeOne(7)
        pa &= 6
        self.assertEqual(pa, 6)
        pa |= 16
        self.assertEqual(pa, 22)
        pa ^= 2
        self.assertEqual(pa, 20)

    @unittest.skipIf(PY3, "No coercion in Py3")
    def test_coerce(self):
        # Before 2.3, coerce() of two proxies returns them unchanged

        x = self._makeOne(1)
        y = self._makeOne(2)
        a, b = coerce(x, y)
        self.assertTrue(a is x and b is y)

        x = self._makeOne(1)
        y = self._makeOne(2.1)
        a, b = coerce(x, y)
        self.assertTrue(isinstance(a, float)) # a was coerced
        self.assertFalse(a is x)
        self.assertEqual(a, float(x))
        self.assertTrue(b is y)

        x = self._makeOne(1.1)
        y = self._makeOne(2)
        a, b = coerce(x, y)
        self.assertTrue(a is x)
        self.assertTrue(isinstance(b, float)) # b was coerced
        self.assertFalse(b is y)
        self.assertEqual(b, float(y))

        x = self._makeOne(1)
        y = 2
        a, b = coerce(x, y)
        self.assertTrue(a is x) # neither was coerced
        self.assertTrue(b is y)

        x = self._makeOne(1)
        y = 2.1
        a, b = coerce(x, y)
        self.assertTrue(isinstance(a, float)) # a was coerced
        self.assertFalse(a is x)
        self.assertEqual(a, float(x))
        self.assertTrue(b is y)

        x = self._makeOne(1.1)
        y = 2
        a, b = coerce(x, y)
        self.assertTrue(a is x)
        self.assertTrue(isinstance(b, float)) # b was coerced
        self.assertFalse(b is y)
        self.assertEqual(b,float(y))

        x = 1
        y = self._makeOne(2)
        a, b = coerce(x, y)
        self.assertTrue(a is x) # neither was coerced
        self.assertTrue(b is y)

        x = 1.1
        y = self._makeOne(2)
        a, b = coerce(x, y)
        self.assertTrue(a is x)
        self.assertTrue(isinstance(b, float)) # b was coerced
        self.assertFalse(b is y)
        self.assertEqual(b,  float(y))

        x = 1
        y = self._makeOne(2.1)
        a, b = coerce(x, y)
        self.assertTrue(isinstance(a, float)) # a was coerced
        self.assertFalse(a is x)
        self.assertEqual(a,  float(x))
        self.assertTrue(b is y)

    def test___class__(self):
        o = object()
        w = self._makeOne(o)
        self.assertTrue(w.__class__ is o.__class__)

    def test_descriptor__set___only_in_proxy_subclass(self):

        class Descriptor(object):
            value = None
            instance = None
            def __set__(self, instance, value):
                self.value = value
                self.instance = instance

        descriptor = Descriptor()
        class Proxy(self._getTargetClass()):
            attr = descriptor

        proxy = Proxy(object())
        proxy.attr = 42

        self.assertEqual(proxy.attr, descriptor)
        self.assertEqual(descriptor.value, 42)
        self.assertEqual(descriptor.instance, proxy)

    def test_descriptor__get___set___in_proxy_subclass(self):

        class Descriptor(object):
            value = None
            instance = None
            cls = None

            def __get__(self, instance, cls):
                self.cls = cls
                return self.value

            def __set__(self, instance, value):
                self.value = value
                self.instance = instance

        descriptor = Descriptor()
        descriptor.value = "descriptor value"
        class Proxy(self._getTargetClass()):
            attr = descriptor

        proxy = Proxy(object())
        self.assertEqual(proxy.attr, "descriptor value")
        self.assertEqual(descriptor.cls, Proxy)

        proxy.attr = 42

        self.assertEqual(descriptor.value, 42)
        self.assertEqual(descriptor.instance, proxy)

    def test_non_descriptor_in_proxy_subclass__dict__(self):
        # Non-descriptors in the class dict of the subclass
        # are always passed through to the wrapped instance
        class Proxy(self._getTargetClass()):
            attr = "constant value"

        proxy = Proxy(object())
        self.assertEqual(proxy.attr, "constant value")

        self.assertRaises(AttributeError, setattr, proxy, 'attr', 42)
        self.assertEqual(proxy.attr, "constant value")

    def _check_wrapping_builtin_returns_correct_provided_by(self, proxy_class, builtin_type):
        # We get the __implemented__ (fallback) of the type, not our own
        from zope.interface import Interface
        from zope.interface import classImplements
        from zope.interface import classImplementsOnly
        from zope.interface import implementedBy
        from zope.interface import providedBy
        from zope.interface import implementedBy

        # Set up the builtin interface
        class IFoo(Interface):
            pass
        impl_before = list(implementedBy(builtin_type))

        classImplements(builtin_type, IFoo)

        builtin = builtin_type()
        self.assertTrue(IFoo in list(providedBy(builtin)))
        self.assertTrue(IFoo in list(implementedBy(builtin_type)))

        try:
            # The asserts must be before we remove the interface
            # because there's a single object that gets mutated

            proxy_instance = proxy_class(builtin)
            provided_instance = providedBy(proxy_instance)
            self.assertTrue(IFoo in list(provided_instance))

            proxy_type = proxy_class(builtin_type)
            from zope.interface.declarations import BuiltinImplementationSpecifications
            self.assertIn(proxy_type, BuiltinImplementationSpecifications)
            self.assertIsNot(BuiltinImplementationSpecifications.get(proxy_type, self),
                             self)
            provided_type = implementedBy(proxy_type)
            self.assertTrue(IFoo in list(provided_type))
        finally:
            classImplementsOnly(builtin_type, *impl_before)

    def test_wrapping_builtin_type_returns_correct_provided_by(self):
        self._check_wrapping_builtin_returns_correct_provided_by(self._getTargetClass(), list)

    def _check_wrapping_builtin_with_subclass_returns_correct_provided_by(self, builtin_type):
        class Proxy(self._getTargetClass()):
            pass

        self._check_wrapping_builtin_returns_correct_provided_by(Proxy, builtin_type)
        # Our new class did not gain an __implemented__ attribute, unless we're
        # the pure-python version
        if hasattr(Proxy, '__implemented__'): # pragma: no cover
            from zope.proxy import PyProxyBase
            self.assertTrue(self._getTargetClass() is PyProxyBase)

    def test_wrapping_builtin_with_subclass_returns_correct_provided_by(self):
        self._check_wrapping_builtin_with_subclass_returns_correct_provided_by(list)

    def test_method_in_proxy_subclass(self):
        class Proxy(self._getTargetClass()):
            def __getitem__(self, k):
                return k

        proxy = Proxy(object())
        # Both when called by the interpreter, which bypasses
        # __getattribute__
        self.assertEqual(proxy[42], 42)
        # And when asked for as an attribute
        self.assertNotEqual(getattr(proxy, '__getitem__'), self)

    def test_string_to_int(self):
        proxy = self._makeOne("14")
        self.assertEqual(14, int(proxy))

class ProxyBaseTestCase(PyProxyBaseTestCase):

    def _getTargetClass(self):
        from zope.proxy import ProxyBase
        return ProxyBase

class Test_py__module(unittest.TestCase):
    # Historically, proxying __module__ has been troublesome,
    # especially when subclasses of the proxy class are involved;
    # there was also a discrepancy between the C and Python implementations
    # in that the C implementation only failed Test_subclass__module:test__module__in_instance,
    # whereas the Python version failed every test.
    # See https://github.com/zopefoundation/zopetoolkit/pull/2#issuecomment-106075153
    # and https://github.com/zopefoundation/zope.proxy/pull/8

    def _getTargetClass(self):
        from zope.proxy import PyProxyBase
        return PyProxyBase

    def _makeProxy(self, obj):
        from zope.proxy import PyProxyBase
        return self._getTargetClass()(obj)

    def _check_module(self, obj, expected):
        self.assertEqual(expected, obj.__module__)
        self.assertEqual(expected, self._makeProxy(obj).__module__)

    def test__module__in_instance(self):
        # We can find __module__ in an instance dict
        class Module(object):
            def __init__(self):
                self.__module__ = 'module'

        self._check_module(Module(), 'module')

    def test__module__in_class_instance(self):
        # We can find module in an instance of a class
        class Module(object):
            pass

        self._check_module(Module(), __name__)

    def test__module__in_class(self):
        # We can find module in a class itself
        class Module(object):
            pass
        self._check_module(Module, __name__)

    def test__module_in_eq_transitive(self):
        # An object that uses __module__ in its implementation
        # of __eq__ is transitively equal to a proxy of itself.
        # Seen with zope.interface.interface.Interface

        class Module(object):
            def __init__(self):
                self.__module__ = __name__
            def __eq__(self, other):
                return self.__module__ == other.__module__

        module = Module()
        # Sanity checks
        self.assertEqual(module, module)
        self.assertEqual(module.__module__, __name__)

        # transitive equal
        self.assertEqual(module, self._makeProxy(module))
        self.assertEqual(self._makeProxy(module), module)

class Test__module(Test_py__module):

    def _getTargetClass(self):
        from zope.proxy import ProxyBase
        return ProxyBase

class Test_py_subclass__module(Test_py__module):

    def _getTargetClass(self):
        class ProxySubclass(super(Test_py_subclass__module, self)._getTargetClass()):
            pass
        return ProxySubclass

class Test_subclass__module(Test__module):

    def _getTargetClass(self):
        class ProxySubclass(super(Test_subclass__module, self)._getTargetClass()):
            pass
        return ProxySubclass


class Test_py_getProxiedObject(unittest.TestCase):

    def _callFUT(self, *args):
        from zope.proxy import py_getProxiedObject
        return py_getProxiedObject(*args)

    def _makeProxy(self, obj):
        from zope.proxy import PyProxyBase
        return PyProxyBase(obj)

    def test_no_proxy(self):
        class C(object):
            pass
        c = C()
        self.assertTrue(self._callFUT(c) is c)

    def test_simple_proxy(self):
        class C(object):
            pass
        c = C()
        proxy = self._makeProxy(c)
        self.assertTrue(self._callFUT(proxy) is c)

    def test_nested_proxy(self):
        class C(object):
            pass
        c = C()
        proxy = self._makeProxy(c)
        proxy2 = self._makeProxy(proxy)
        self.assertTrue(self._callFUT(proxy2) is proxy)

class Test_getProxiedObject(Test_py_getProxiedObject):

    def _callFUT(self, *args):
        from zope.proxy import getProxiedObject
        return getProxiedObject(*args)

    def _makeProxy(self, obj):
        from zope.proxy import ProxyBase
        return ProxyBase(obj)


class Test_py_setProxiedObject(unittest.TestCase):

    def _callFUT(self, *args):
        from zope.proxy import py_setProxiedObject
        return py_setProxiedObject(*args)

    def _makeProxy(self, obj):
        from zope.proxy import PyProxyBase
        return PyProxyBase(obj)

    def test_no_proxy(self):
        class C(object):
            pass
        c1 = C()
        c2 = C()
        self.assertRaises(TypeError, self._callFUT, c1, c2)

    def test_w_proxy(self):
        class C(object):
            def __init__(self, name):
                self.name = name
        c1 = C('c1')
        c2 = C('c2')
        proxy = self._makeProxy(c1)
        self.assertEqual(proxy.name, 'c1')
        old = self._callFUT(proxy, c2)
        self.assertTrue(old is c1)
        self.assertEqual(proxy.name, 'c2')

    def test_w_nested_proxy(self):
        class C(object):
            def __init__(self, name):
                self.name = name
        c1 = C('c1')
        c2 = C('c2')
        p1 = self._makeProxy(c1)
        proxy2 = self._makeProxy(c2)
        proxy = self._makeProxy(p1)
        self.assertEqual(proxy.name, 'c1')
        old = self._callFUT(proxy, proxy2)
        self.assertTrue(old is p1)
        self.assertEqual(proxy.name, 'c2')


class Test_setProxiedObject(Test_py_setProxiedObject):

    def _callFUT(self, *args):
        from zope.proxy import setProxiedObject
        return setProxiedObject(*args)

    def _makeProxy(self, obj):
        from zope.proxy import ProxyBase
        return ProxyBase(obj)


class Test_py_isProxy(unittest.TestCase):

    def _callFUT(self, *args):
        from zope.proxy import py_isProxy
        return py_isProxy(*args)

    def _proxyClass(self):
        from zope.proxy import PyProxyBase
        return PyProxyBase

    def test_bare_instance(self):
        class C(object):
            pass
        c = C()
        self.assertFalse(self._callFUT(c))

    def test_proxy_no_class(self):
        class P1(self._proxyClass()):
            pass
        class C(object):
            pass
        c = C()
        p1 = P1(c)
        self.assertTrue(self._callFUT(p1))

    def test_proxy_w_same_class(self):
        class P1(self._proxyClass()):
            pass
        class C(object):
            pass
        c = C()
        p1 = P1(c)
        self.assertTrue(self._callFUT(p1, P1))

    def test_proxy_w_other_class(self):
        class P1(self._proxyClass()):
            pass
        class P2(self._proxyClass()):
            pass
        class C(object):
            pass
        c = C()
        p1 = P1(c)
        self.assertFalse(self._callFUT(p1, P2))


class Test_isProxy(Test_py_isProxy):

    def _callFUT(self, *args):
        from zope.proxy import isProxy
        return isProxy(*args)

    def _proxyClass(self):
        from zope.proxy import ProxyBase
        return ProxyBase


class Test_py_sameProxiedObjects(unittest.TestCase):

    def _callFUT(self, *args):
        from zope.proxy import py_sameProxiedObjects
        return py_sameProxiedObjects(*args)

    def _makeProxy(self, obj):
        from zope.proxy import PyProxyBase
        return PyProxyBase(obj)

    def _makeSecurityProxy(self, obj):
        from zope.security.proxy import ProxyPy
        from zope.security.checker import CheckerPy
        checker = CheckerPy({})
        return ProxyPy(obj, checker)

    def test_bare_instance_identical(self):
        class C(object):
            pass
        c1 = C()
        self.assertTrue(self._callFUT(c1, c1))

    def test_bare_instances_different(self):
        class C(object):
            pass
        c1 = C()
        c2 = C()
        self.assertFalse(self._callFUT(c1, c2))
        self.assertFalse(self._callFUT(c2, c1))

    def test_proxy_and_same_bare(self):
        class C(object):
            pass
        c1 = C()
        self.assertTrue(self._callFUT(self._makeProxy(c1), c1))
        self.assertTrue(self._callFUT(c1, self._makeProxy(c1)))

    def test_proxy_and_other_bare(self):
        class C(object):
            pass
        c1 = C()
        c2 = C()
        self.assertFalse(self._callFUT(self._makeProxy(c1), c2))
        self.assertFalse(self._callFUT(c2, self._makeProxy(c1)))

    def test_proxies_w_same_bare(self):
        _mP = self._makeProxy
        class C(object):
            pass
        c1 = C()
        self.assertTrue(self._callFUT(_mP(c1), _mP(c1)))

    def test_proxies_w_other_bare(self):
        _mP = self._makeProxy
        class C(object):
            pass
        c1 = C()
        c2 = C()
        self.assertFalse(self._callFUT(_mP(c1), _mP(c2)))
        self.assertFalse(self._callFUT(_mP(c2), _mP(c1)))

    def test_nested_proxy_and_same_bare(self):
        _mP = self._makeProxy
        class C(object):
            pass
        c1 = C()
        self.assertTrue(self._callFUT(_mP(_mP(c1)), c1))
        self.assertTrue(self._callFUT(c1, _mP(_mP(c1))))

    def test_nested_proxy_and_other_bare(self):
        _mP = self._makeProxy
        class C(object):
            pass
        c1 = C()
        c2 = C()
        self.assertFalse(self._callFUT(_mP(_mP(c1)), c2))
        self.assertFalse(self._callFUT(c2, _mP(_mP(c1))))

    @unittest.skipUnless(_HAVE_ZOPE_SECURITY, 'zope.security missing')
    def test_security_proxy(self):
        class C(object):
            pass
        c1 = C()
        proxy1 = self._makeSecurityProxy(c1)
        proxy1_2 = self._makeSecurityProxy(c1)

        self.assertTrue(self._callFUT(proxy1, proxy1))
        self.assertTrue(self._callFUT(proxy1, proxy1_2))

        c2 = C()
        proxy2 = self._makeSecurityProxy(c2)
        self.assertFalse(self._callFUT(proxy1, proxy2))

class Test_sameProxiedObjects(Test_py_sameProxiedObjects):

    def _callFUT(self, *args):
        from zope.proxy import sameProxiedObjects
        return sameProxiedObjects(*args)

    def _makeProxy(self, obj):
        from zope.proxy import ProxyBase
        return ProxyBase(obj)

    def _makeSecurityProxy(self, obj):
        from zope.security.proxy import Proxy
        from zope.security.checker import Checker
        checker = Checker({})
        return Proxy(obj, checker)

class Test_py_queryProxy(unittest.TestCase):

    def _callFUT(self, *args):
        from zope.proxy import py_queryProxy
        return py_queryProxy(*args)

    def _proxyClass(self):
        from zope.proxy import PyProxyBase
        return PyProxyBase

    def test_bare_instance(self):
        class C(object):
            pass
        c = C()
        self.assertEqual(self._callFUT(c), None)

    def test_proxy_no_class(self):
        class P1(self._proxyClass()):
            pass
        class C(object):
            pass
        c = C()
        p1 = P1(c)
        self.assertTrue(self._callFUT(p1) is p1)

    def test_proxy_w_same_class(self):
        class P1(self._proxyClass()):
            pass
        class C(object):
            pass
        c = C()
        p1 = P1(c)
        self.assertTrue(self._callFUT(p1, P1) is p1)
        self.assertTrue(self._callFUT(p1, P1, 42) is p1)

    def test_proxy_w_other_class(self):
        class P1(self._proxyClass()):
            pass
        class P2(self._proxyClass()):
            pass
        class C(object):
            pass
        c = C()
        p1 = P1(c)
        self.assertEqual(self._callFUT(p1, P2), None)
        self.assertEqual(self._callFUT(p1, P2, 42), 42)

    def test_proxy_w_base_class(self):
        class P1(self._proxyClass()):
            pass
        class P2(self._proxyClass()):
            pass
        class C(object):
            pass
        c = C()
        p1 = P1(c)
        self.assertTrue(self._callFUT(p1, self._proxyClass()) is p1)
        self.assertTrue(self._callFUT(p1, self._proxyClass(), 42) is p1)


class Test_queryProxy(Test_py_queryProxy):

    def _callFUT(self, *args):
        from zope.proxy import queryProxy
        return queryProxy(*args)

    def _proxyClass(self):
        from zope.proxy import ProxyBase
        return ProxyBase


class Test_py_queryInnerProxy(unittest.TestCase):

    def _callFUT(self, *args):
        from zope.proxy import py_queryInnerProxy
        return py_queryInnerProxy(*args)

    def _proxyClass(self):
        from zope.proxy import PyProxyBase
        return PyProxyBase

    def test_bare_instance(self):
        class C(object):
            pass
        c = C()
        self.assertEqual(self._callFUT(c), None)

    def test_proxy_no_class(self):
        class P1(self._proxyClass()):
            pass
        class C(object):
            pass
        c = C()
        p1 = P1(c)
        self.assertTrue(self._callFUT(p1) is p1)

    def test_proxy_w_same_class(self):
        class P1(self._proxyClass()):
            pass
        class C(object):
            pass
        c = C()
        p1 = P1(c)
        self.assertTrue(self._callFUT(p1, P1) is p1)
        self.assertTrue(self._callFUT(p1, P1, 42) is p1)

    def test_nested_proxy(self):
        class P1(self._proxyClass()):
            pass
        class P2(self._proxyClass()):
            pass
        class C(object):
            pass
        c = C()
        p1 = P1(c)
        proxy2 = P2(p1)
        self.assertTrue(self._callFUT(proxy2, P1) is p1)
        self.assertTrue(self._callFUT(proxy2, P1, 42) is p1)
        self.assertTrue(self._callFUT(proxy2, P2) is proxy2)
        self.assertTrue(self._callFUT(proxy2, P2, 42) is proxy2)

    def test_re_nested_proxy(self):
        class P1(self._proxyClass()):
            pass
        class P2(self._proxyClass()):
            pass
        class C(object):
            pass
        c = C()
        p1 = P1(c)
        proxy2 = P2(p1)
        proxy3 = P1(proxy2)
        self.assertTrue(self._callFUT(proxy3, P1) is p1)
        self.assertTrue(self._callFUT(proxy3, P1, 42) is p1)
        self.assertTrue(self._callFUT(proxy3, P2) is proxy2)
        self.assertTrue(self._callFUT(proxy3, P2, 42) is proxy2)


class Test_queryInnerProxy(Test_py_queryInnerProxy):

    def _callFUT(self, *args):
        from zope.proxy import queryInnerProxy
        return queryInnerProxy(*args)

    def _proxyClass(self):
        from zope.proxy import ProxyBase
        return ProxyBase


class Test_py_removeAllProxies(unittest.TestCase):

    def _callFUT(self, *args):
        from zope.proxy import py_removeAllProxies
        return py_removeAllProxies(*args)

    def _makeProxy(self, obj):
        from zope.proxy import PyProxyBase
        return PyProxyBase(obj)

    def _makeSecurityProxy(self, obj):
        from zope.security.proxy import ProxyPy
        checker = object()
        return ProxyPy(obj, checker)

    def test_no_proxy(self):
        class C(object):
            pass
        c = C()
        self.assertTrue(self._callFUT(c) is c)

    def test_simple_proxy(self):
        class C(object):
            pass
        c = C()
        proxy = self._makeProxy(c)
        self.assertTrue(self._callFUT(proxy) is c)

    def test_nested_proxy(self):
        class C(object):
            pass
        c = C()
        proxy = self._makeProxy(c)
        proxy2 = self._makeProxy(proxy)
        self.assertTrue(self._callFUT(proxy2) is c)

    @unittest.skipUnless(_HAVE_ZOPE_SECURITY, 'zope.security missing')
    def test_security_proxy(self):
        class C(object):
            pass
        c = C()
        proxy = self._makeSecurityProxy(c)
        self.assertIs(self._callFUT(proxy), c)

class Test_removeAllProxies(Test_py_removeAllProxies):

    def _callFUT(self, *args):
        from zope.proxy import removeAllProxies
        return removeAllProxies(*args)

    def _makeProxy(self, obj):
        from zope.proxy import ProxyBase
        return ProxyBase(obj)

    def _makeSecurityProxy(self, obj):
        from zope.security.proxy import Proxy
        checker = object()
        return Proxy(obj, checker)

class Test_ProxyIterator(unittest.TestCase):

    def _callFUT(self, *args):
        from zope.proxy import ProxyIterator
        return ProxyIterator(*args)

    def test_no_proxy(self):
        class C(object):
            pass
        c = C()
        self.assertEqual(list(self._callFUT(c)), [c])

    def test_w_simple_proxy(self):
        from zope.proxy import ProxyBase
        class C(object):
            pass
        c = C()
        proxy = ProxyBase(c)
        self.assertEqual(list(self._callFUT(proxy)), [proxy, c])

    def test_w_nested_proxies(self):
        from zope.proxy import ProxyBase
        class C(object):
            pass
        c = C()
        proxy = ProxyBase(c)
        proxy2 = ProxyBase(proxy)
        proxy3 = ProxyBase(proxy2)
        proxy4 = ProxyBase(proxy3)
        self.assertEqual(list(self._callFUT(proxy4)),
                         [proxy4, proxy3, proxy2, proxy, c])


class Test_nonOverridable(unittest.TestCase):

    def test_it(self):
        from zope.proxy import ProxyBase
        from zope.proxy import non_overridable
        class Proxy(ProxyBase):
            def who(self):
                raise AssertionError("Not called")
            @non_overridable
            def what(self):
                return 'PROXY'
        class Foo(object):
            def who(self):
                return 'FOO'
            def what(self):
                return 'FOO'
        p0 = ProxyBase(Foo())
        self.assertEqual(p0.who(), 'FOO')
        self.assertEqual(p0.what(), 'FOO')
        proxy = Proxy(Foo())
        self.assertEqual(proxy.who(), 'FOO')
        self.assertEqual(proxy.what(), 'PROXY')


class TestEmptyInterfaceDescriptor(unittest.TestCase):

    def _makeOne(self):
        from zope.proxy import _EmptyInterfaceDescriptor
        class It(object):
            feature = _EmptyInterfaceDescriptor()
        return It()

    def test_set(self):
        it = self._makeOne()
        with self.assertRaises(TypeError):
            it.feature = 42

    def test_delete(self):
        it = self._makeOne()
        del it.feature
        with self.assertRaises(AttributeError):
            getattr(it, 'feature')

    def test_iter(self):
        it = type(self._makeOne())
        feature = it.__dict__['feature']
        self.assertEqual([], list(feature))


class Comparable(object):
    def __init__(self, value):
        self.value = value

    def __eq__(self, other):
        return self.value == getattr(other, 'value', other)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __lt__(self, other):
        return self.value < getattr(other, 'value', other)

    def __ge__(self, other):
        return not self.__lt__(other)

    def __le__(self, other):
        return self.value <= getattr(other, 'value', other)

    def __gt__(self, other):
        return not self.__le__(other)

    def __repr__(self): # pragma: no cover
        return "<Comparable: %r>" % self.value


def test_suite():
    return unittest.defaultTestLoader.loadTestsFromName(__name__)
