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
"""Test Harness
"""
import unittest


class DecoratorSpecificationDescriptorTests(unittest.TestCase):

    def _getTargetClass(self):
        from zope.proxy.decorator import DecoratorSpecificationDescriptor
        return DecoratorSpecificationDescriptor

    def _makeOne(self):
        return self._getTargetClass()()

    def test___get___w_class(self):
        from zope.interface import Interface
        from zope.interface import implementer
        from zope.interface import provider
        class IContextFactory(Interface):
            pass
        class IContext(Interface):
            pass
        @provider(IContextFactory)
        @implementer(IContext)
        class Context(object):
            pass
        dsd = self._makeOne()
        self.assertEqual(list(dsd.__get__(None, Context)), [IContextFactory])

    def test___get___w_inst_no_proxy(self):
        from zope.interface import Interface
        from zope.interface import implementer
        from zope.interface import provider
        class IContextFactory(Interface):
            pass
        class IContext(Interface):
            pass
        @provider(IContextFactory)
        @implementer(IContext)
        class Context(object):
            pass
        dsd = self._makeOne()
        self.assertEqual(list(dsd.__get__(Context(), None)), [IContext])

    def test___get___w_inst_w_proxy(self):
        from zope.interface import Interface
        from zope.interface import implementer
        from zope.interface import provider
        from zope.proxy import ProxyBase
        class IContextFactory(Interface):
            pass
        class IContext(Interface):
            pass
        @provider(IContextFactory)
        @implementer(IContext)
        class Context(object):
            pass
        context = Context()
        proxy = ProxyBase(context)
        dsd = self._makeOne()
        self.assertEqual(list(dsd.__get__(proxy, None)), [IContext])

    def test___get___w_inst_w_derived_proxy(self):
        from zope.interface import Interface
        from zope.interface import implementer
        from zope.interface import provider
        from zope.proxy import ProxyBase
        class IContextFactory(Interface):
            pass
        class IContext(Interface):
            pass
        @provider(IContextFactory)
        @implementer(IContext)
        class Context(object):
            pass
        class IProxyFactory(Interface):
            pass
        class IProxy(Interface):
            pass
        @provider(IProxyFactory)
        @implementer(IProxy)
        class Proxy(ProxyBase):
            pass
        context = Context()
        proxy = Proxy(context)
        dsd = self._makeOne()
        self.assertEqual(list(dsd.__get__(proxy, None)),
                         [IContext, IProxy])

    def test___set___not_allowed(self):
        from zope.interface import Interface
        from zope.interface import implementer
        class IFoo(Interface):
            pass
        @implementer(IFoo)
        class Foo(object):
            pass
        foo = Foo()
        dsd = self._makeOne()
        self.assertRaises(TypeError, dsd.__set__, foo, object())


class SpecificationDecoratorBaseTests(unittest.TestCase):

    def _getTargetClass(self):
        from zope.proxy.decorator import SpecificationDecoratorBase
        return SpecificationDecoratorBase

    def _makeOne(self, wrapped):
        return self._getTargetClass()(wrapped)

    def test_wrapped_instance(self):
        from zope.interface import Interface
        from zope.interface import implementer
        from zope.interface import providedBy
        class IFoo(Interface):
            pass
        @implementer(IFoo)
        class Foo(object):
            pass
        foo = Foo()
        proxy = self._makeOne(foo)
        self.assertEqual(list(providedBy(proxy)), list(providedBy(foo)))

    def test_proxy_that_provides_interface_as_well_as_wrapped(self):
        # If both the wrapper and the wrapped object provide
        # interfaces, the wrapper provides the sum
        from zope.interface import Interface
        from zope.interface import implementer
        from zope.interface import providedBy
        class IFoo(Interface):
            pass
        @implementer(IFoo)
        class Foo(object):
            from_foo = 1

        class IWrapper(Interface):
            pass
        @implementer(IWrapper)
        class Proxy(self._getTargetClass()):
            pass

        foo = Foo()
        proxy = Proxy(foo)

        self.assertEqual(proxy.from_foo, 1)
        self.assertEqual(list(providedBy(proxy)), [IFoo,IWrapper])


def test_suite():
    return unittest.TestSuite((
        unittest.makeSuite(DecoratorSpecificationDescriptorTests),
        unittest.makeSuite(SpecificationDecoratorBaseTests),
    ))
