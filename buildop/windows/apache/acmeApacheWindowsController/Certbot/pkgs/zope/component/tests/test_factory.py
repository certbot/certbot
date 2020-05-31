##############################################################################
#
# Copyright (c) 2012 Zope Foundation and Contributors.
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
"""Tests for z.c.factory
"""
import unittest

from zope.component.tests import fails_if_called

class FactoryTests(unittest.TestCase):

    def _getTargetClass(self):
        from zope.component.factory import Factory
        return Factory

    def _makeOne(self, callable=None, *args, **kw):
        if callable is None:
            callable = fails_if_called(self)
        return self._getTargetClass()(callable, *args, **kw)

    def test_class_conforms_to_IFactory(self):
        from zope.interface.verify import verifyClass
        from zope.component.interfaces import IFactory
        verifyClass(IFactory, self._getTargetClass())

    def test_instance_conforms_to_IFactory(self):
        from zope.interface.verify import verifyObject
        from zope.component.interfaces import IFactory
        verifyObject(IFactory, self._makeOne())

    def test_ctor_defaults(self):
        func = fails_if_called(self)
        factory = self._makeOne(func)
        self.assertEqual(factory._callable, func)
        self.assertEqual(factory.title, '')
        self.assertEqual(factory.description, '')
        self.assertEqual(factory._interfaces, None)

    def test_ctor_expclit(self):
        factory = self._makeOne(fails_if_called(self), 'TITLE', 'DESCRIPTION')
        self.assertEqual(factory.title, 'TITLE')
        self.assertEqual(factory.description, 'DESCRIPTION')

    def test___call___no_args(self):
        _called = []
        def _callable(*args, **kw):
            _called.append((args, kw))
        factory = self._makeOne(_callable)
        factory()
        self.assertEqual(_called, [((), {})])

    def test___call___positional_args(self):
        _called = []
        def _callable(*args, **kw):
            _called.append((args, kw))
        factory = self._makeOne(_callable)
        factory('one', 'two')
        self.assertEqual(_called, [(('one', 'two'), {})])

    def test___call___keyword_args(self):
        _called = []
        def _callable(*args, **kw):
            _called.append((args, kw))
        factory = self._makeOne(_callable)
        factory(foo='bar')
        self.assertEqual(_called, [((), {'foo': 'bar'})])

    def test_getInterfaces_explicit(self):
        from zope.interface import Interface
        from zope.interface import implementer
        class IFoo(Interface):
            pass
        class IBar(Interface):
            pass
        class IBaz(Interface):
            pass
        _callable = fails_if_called(self)
        _callable.__name__ = '_callable'
        _callable = implementer(IBaz)(_callable)
        factory = self._makeOne(_callable, interfaces=(IFoo, IBar))
        spec = factory.getInterfaces()
        self.assertEqual(spec.__name__, '_callable')
        self.assertEqual(list(spec), [IFoo, IBar])

    def test_getInterfaces_implicit(self):
        from zope.interface import Interface
        from zope.interface import implementer
        class IBaz(Interface):
            pass
        _callable = implementer(IBaz)(fails_if_called(self))
        factory = self._makeOne(_callable)
        spec = factory.getInterfaces()
        self.assertEqual(list(spec), [IBaz])
