##############################################################################
#
# Copyright (c) 2001, 2002 Zope Foundation and Contributors.
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
""" zope.interface.verify unit tests
"""
import unittest


class Test_verifyClass(unittest.TestCase):

    def _callFUT(self, iface, klass):
        from zope.interface.verify import verifyClass
        return verifyClass(iface, klass)

    def test_class_doesnt_implement(self):
        from zope.interface import Interface
        from zope.interface.exceptions import DoesNotImplement

        class ICurrent(Interface):
            pass

        class Current(object):
            pass

        self.assertRaises(DoesNotImplement, self._callFUT, ICurrent, Current)

    def test_class_doesnt_implement_but_classImplements_later(self):
        from zope.interface import Interface
        from zope.interface import classImplements

        class ICurrent(Interface):
            pass

        class Current(object):
            pass

        classImplements(Current, ICurrent)

        self._callFUT(ICurrent, Current)

    def test_class_doesnt_have_required_method_simple(self):
        from zope.interface import Interface
        from zope.interface import implementer
        from zope.interface.exceptions import BrokenImplementation

        class ICurrent(Interface):
            def method(): pass

        @implementer(ICurrent)
        class Current(object):
            pass

        self.assertRaises(BrokenImplementation,
                          self._callFUT, ICurrent, Current)

    def test_class_has_required_method_simple(self):
        from zope.interface import Interface
        from zope.interface import implementer

        class ICurrent(Interface):
            def method(): pass

        @implementer(ICurrent)
        class Current(object):

            def method(self):
                raise NotImplementedError()

        self._callFUT(ICurrent, Current)

    def test_class_doesnt_have_required_method_derived(self):
        from zope.interface import Interface
        from zope.interface import implementer
        from zope.interface.exceptions import BrokenImplementation

        class IBase(Interface):
            def method():
                pass

        class IDerived(IBase):
            pass

        @implementer(IDerived)
        class Current(object):
            pass

        self.assertRaises(BrokenImplementation,
                          self._callFUT, IDerived, Current)

    def test_class_has_required_method_derived(self):
        from zope.interface import Interface
        from zope.interface import implementer

        class IBase(Interface):
            def method():
                pass

        class IDerived(IBase):
            pass

        @implementer(IDerived)
        class Current(object):

            def method(self):
                raise NotImplementedError()

        self._callFUT(IDerived, Current)

    def test_method_takes_wrong_arg_names_but_OK(self):
        # We no longer require names to match.
        from zope.interface import Interface
        from zope.interface import implementer

        class ICurrent(Interface):

            def method(a):
                pass

        @implementer(ICurrent)
        class Current(object):

            def method(self, b):
                raise NotImplementedError()

        self._callFUT(ICurrent, Current)

    def test_method_takes_not_enough_args(self):
        from zope.interface import Interface
        from zope.interface import implementer
        from zope.interface.exceptions import BrokenMethodImplementation

        class ICurrent(Interface):

            def method(a):
                pass

        @implementer(ICurrent)
        class Current(object):

            def method(self):
                raise NotImplementedError()

        self.assertRaises(BrokenMethodImplementation,
                          self._callFUT, ICurrent, Current)

    def test_method_doesnt_take_required_starargs(self):
        from zope.interface import Interface
        from zope.interface import implementer
        from zope.interface.exceptions import BrokenMethodImplementation

        class ICurrent(Interface):

            def method(*args):
                pass

        @implementer(ICurrent)
        class Current(object):

            def method(self):
                raise NotImplementedError()

        self.assertRaises(BrokenMethodImplementation,
                          self._callFUT, ICurrent, Current)

    def test_method_doesnt_take_required_only_kwargs(self):
        from zope.interface import Interface
        from zope.interface import implementer
        from zope.interface.exceptions import BrokenMethodImplementation

        class ICurrent(Interface):

            def method(**kw):
                pass

        @implementer(ICurrent)
        class Current(object):

            def method(self):
                raise NotImplementedError()

        self.assertRaises(BrokenMethodImplementation,
                          self._callFUT, ICurrent, Current)

    def test_method_takes_extra_arg(self):
        from zope.interface import Interface
        from zope.interface import implementer
        from zope.interface.exceptions import BrokenMethodImplementation

        class ICurrent(Interface):

            def method(a):
                pass

        @implementer(ICurrent)
        class Current(object):

            def method(self, a, b):
                raise NotImplementedError()

        self.assertRaises(BrokenMethodImplementation,
                          self._callFUT, ICurrent, Current)

    def test_method_takes_extra_arg_with_default(self):
        from zope.interface import Interface
        from zope.interface import implementer

        class ICurrent(Interface):

            def method(a):
                pass

        @implementer(ICurrent)
        class Current(object):

            def method(self, a, b=None):
                raise NotImplementedError()

        self._callFUT(ICurrent, Current)

    def test_method_takes_only_positional_args(self):
        from zope.interface import Interface
        from zope.interface import implementer

        class ICurrent(Interface):

            def method(a):
                pass

        @implementer(ICurrent)
        class Current(object):

            def method(self, *args):
                raise NotImplementedError()

        self._callFUT(ICurrent, Current)

    def test_method_takes_only_kwargs(self):
        from zope.interface import Interface
        from zope.interface import implementer
        from zope.interface.exceptions import BrokenMethodImplementation

        class ICurrent(Interface):

            def method(a):
                pass

        @implementer(ICurrent)
        class Current(object):

            def method(self, **kw):
                raise NotImplementedError()

        self.assertRaises(BrokenMethodImplementation,
                          self._callFUT, ICurrent, Current)

    def test_method_takes_extra_starargs(self):
        from zope.interface import Interface
        from zope.interface import implementer

        class ICurrent(Interface):

            def method(a):
                pass

        @implementer(ICurrent)
        class Current(object):

            def method(self, a, *args):
                raise NotImplementedError()

        self._callFUT(ICurrent, Current)

    def test_method_takes_extra_starargs_and_kwargs(self):
        from zope.interface import Interface
        from zope.interface import implementer

        class ICurrent(Interface):

            def method(a):
                pass

        @implementer(ICurrent)
        class Current(object):

            def method(self, a, *args, **kw):
                raise NotImplementedError()

        self._callFUT(ICurrent, Current)

    def test_method_doesnt_take_required_positional_and_starargs(self):
        from zope.interface import Interface
        from zope.interface import implementer
        from zope.interface.exceptions import BrokenMethodImplementation

        class ICurrent(Interface):

            def method(a, *args):
                pass

        @implementer(ICurrent)
        class Current(object):

            def method(self, a):
                raise NotImplementedError()

        self.assertRaises(BrokenMethodImplementation,
                          self._callFUT, ICurrent, Current)

    def test_method_takes_required_positional_and_starargs(self):
        from zope.interface import Interface
        from zope.interface import implementer

        class ICurrent(Interface):

            def method(a, *args):
                pass

        @implementer(ICurrent)
        class Current(object):

            def method(self, a, *args):
                raise NotImplementedError()

        self._callFUT(ICurrent, Current)

    def test_method_takes_only_starargs(self):
        from zope.interface import Interface
        from zope.interface import implementer

        class ICurrent(Interface):

            def method(a, *args):
                pass

        @implementer(ICurrent)
        class Current(object):

            def method(self, *args):
                raise NotImplementedError()

        self._callFUT(ICurrent, Current)

    def test_method_takes_required_kwargs(self):
        from zope.interface import Interface
        from zope.interface import implementer

        class ICurrent(Interface):

            def method(**kwargs):
                pass

        @implementer(ICurrent)
        class Current(object):

            def method(self, **kw):
                raise NotImplementedError()

        self._callFUT(ICurrent, Current)

    def test_method_takes_positional_plus_required_starargs(self):
        from zope.interface import Interface
        from zope.interface import implementer
        from zope.interface.exceptions import BrokenMethodImplementation

        class ICurrent(Interface):

            def method(*args):
                pass

        @implementer(ICurrent)
        class Current(object):

            def method(self, a, *args):
                raise NotImplementedError()

        self.assertRaises(BrokenMethodImplementation,
                          self._callFUT, ICurrent, Current)


    def test_method_doesnt_take_required_kwargs(self):
        from zope.interface import Interface
        from zope.interface import implementer
        from zope.interface.exceptions import BrokenMethodImplementation

        class ICurrent(Interface):

            def method(**kwargs):
                pass

        @implementer(ICurrent)
        class Current(object):

            def method(self, a):
                raise NotImplementedError()

        self.assertRaises(BrokenMethodImplementation,
                          self._callFUT, ICurrent, Current)


    def test_class_has_method_for_iface_attr(self):
        from zope.interface import Attribute
        from zope.interface import Interface
        from zope.interface import implementer

        class ICurrent(Interface):
            attr = Attribute("The foo Attribute")

        @implementer(ICurrent)
        class Current:

            def attr(self):
                raise NotImplementedError()

        self._callFUT(ICurrent, Current)

    def test_class_has_nonmethod_for_method(self):
        from zope.interface import Interface
        from zope.interface import implementer
        from zope.interface.exceptions import BrokenMethodImplementation

        class ICurrent(Interface):
            def method():
                pass

        @implementer(ICurrent)
        class Current:
            method = 1

        self.assertRaises(BrokenMethodImplementation,
                          self._callFUT, ICurrent, Current)

    def test_class_has_attribute_for_attribute(self):
        from zope.interface import Attribute
        from zope.interface import Interface
        from zope.interface import implementer

        class ICurrent(Interface):
            attr = Attribute("The foo Attribute")

        @implementer(ICurrent)
        class Current:

            attr = 1

        self._callFUT(ICurrent, Current)

    def test_class_misses_attribute_for_attribute(self):
        # This check *passes* for verifyClass
        from zope.interface import Attribute
        from zope.interface import Interface
        from zope.interface import implementer

        class ICurrent(Interface):
            attr = Attribute("The foo Attribute")

        @implementer(ICurrent)
        class Current:
            pass

        self._callFUT(ICurrent, Current)

    def test_w_callable_non_func_method(self):
        from zope.interface.interface import Method
        from zope.interface import Interface
        from zope.interface import implementer

        class QuasiMethod(Method):
            def __call__(self, *args, **kw):
                raise NotImplementedError()

        class QuasiCallable(object):
            def __call__(self, *args, **kw):
                raise NotImplementedError()

        class ICurrent(Interface):
            attr = QuasiMethod('This is callable')

        @implementer(ICurrent)
        class Current:
            attr = QuasiCallable()

        self._callFUT(ICurrent, Current)


    def test_w_decorated_method(self):
        from zope.interface import Interface
        from zope.interface import implementer

        def decorator(func):
            # this is, in fact, zope.proxy.non_overridable
            return property(lambda self: func.__get__(self))

        class ICurrent(Interface):

            def method(a):
                pass

        @implementer(ICurrent)
        class Current(object):

            @decorator
            def method(self, a):
                raise NotImplementedError()

        self._callFUT(ICurrent, Current)

class Test_verifyObject(Test_verifyClass):

    def _callFUT(self, iface, target):
        from zope.interface.verify import verifyObject
        if isinstance(target, (type, type(OldSkool))):
            target = target()
        return verifyObject(iface, target)

    def test_class_misses_attribute_for_attribute(self):
        # This check *fails* for verifyObject
        from zope.interface import Attribute
        from zope.interface import Interface
        from zope.interface import implementer
        from zope.interface.exceptions import BrokenImplementation

        class ICurrent(Interface):
            attr = Attribute("The foo Attribute")

        @implementer(ICurrent)
        class Current:
            pass

        self.assertRaises(BrokenImplementation,
                          self._callFUT, ICurrent, Current)

    def test_module_hit(self):
        from zope.interface.tests.idummy import IDummyModule
        from zope.interface.tests import dummy

        self._callFUT(IDummyModule, dummy)

    def test_module_miss(self):
        from zope.interface import Interface
        from zope.interface.tests import dummy
        from zope.interface.exceptions import DoesNotImplement

        # same name, different object
        class IDummyModule(Interface):
            pass

        self.assertRaises(DoesNotImplement,
                          self._callFUT, IDummyModule, dummy)

    def test_staticmethod_hit_on_class(self):
        from zope.interface import Interface
        from zope.interface import provider
        from zope.interface.verify import verifyObject

        class IFoo(Interface):

            def bar(a, b):
                "The bar method"

        @provider(IFoo)
        class Foo(object):

            @staticmethod
            def bar(a, b):
                raise AssertionError("We're never actually called")

        # Don't use self._callFUT, we don't want to instantiate the
        # class.
        verifyObject(IFoo, Foo)

class OldSkool:
    pass
