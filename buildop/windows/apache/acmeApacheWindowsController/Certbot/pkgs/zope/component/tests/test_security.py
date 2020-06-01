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
"""
Tests for zope.component.security
"""
import unittest

from zope.component.tests import skipIfNoSecurity
from zope.component.tests import fails_if_called

@skipIfNoSecurity
class PermissionProxyTests(unittest.TestCase):

    def _getTargetClass(self):
        from zope.component.security import PermissionProxy
        return PermissionProxy

    def _makeOne(self, wrapped):
        return self._getTargetClass()(wrapped)

    def test_proxy_delegates___provided_by__(self):
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
        self.assertEqual(providedBy(proxy), providedBy(foo))

@skipIfNoSecurity
class Test__checker(unittest.TestCase):

    def _callFUT(self, *args, **kw):
        from zope.component.security import _checker
        return _checker(*args, **kw)

    def test_no_allowed_attributes_no_allowed_interfaces(self):
        from zope.security.checker import CheckerPublic
        checker = self._callFUT(object(), 'zope.Public', (), ())
        self.assertEqual(checker.get_permissions, {'__call__': CheckerPublic})
        self.assertFalse(checker.set_permissions)

    def test_w_allowed_interfaces(self):
        from zope.interface import Interface
        class IFoo(Interface):
            def bar(self):
                "bar"
            def baz(self):
                "baz"
        class ISpam(Interface):
            def qux(self):
                "qux"
        checker = self._callFUT(object(), 'testing', (IFoo, ISpam), ())
        self.assertEqual(checker.get_permissions,
                        {'bar': 'testing', 'baz': 'testing', 'qux': 'testing'})
        self.assertFalse(checker.set_permissions)

    def test_w_allowed_attributes(self):
        checker = self._callFUT(object(), 'testing', (), ('foo', 'bar'))
        self.assertEqual(checker.get_permissions,
                        {'foo': 'testing', 'bar': 'testing'})
        self.assertFalse(checker.set_permissions)

@skipIfNoSecurity
class Test_proxify(unittest.TestCase):

    def _callFUT(self, *args, **kw):
        from zope.component.security import proxify
        return proxify(*args, **kw)

    def _makeContext(self):
        class _Context(object):
            bar = fails_if_called(self)
        return _Context()

    def test_no_checker_no_provides(self):
        ctx = self._makeContext()
        self.assertRaises(ValueError, self._callFUT, ctx, permission='testing')

    def test_no_checker_no_permission(self):
        from zope.interface import Interface
        class IFoo(Interface):
            def bar(self):
                "bar"
        ctx = self._makeContext()
        self.assertRaises(ValueError, self._callFUT, ctx, provides=IFoo)

    def test_no_checker_w_provides_and_permission_public(self):
        from zope.interface import Interface
        from zope.security.checker import CheckerPublic
        from zope.proxy import getProxiedObject
        class IFoo(Interface):
            def bar(self):
                "bar"
        ctx = self._makeContext()
        proxy = self._callFUT(ctx, provides=IFoo, permission='zope.Public')
        self.assertTrue(getProxiedObject(proxy) is ctx)
        checker = proxy.__Security_checker__
        self.assertEqual(checker.get_permissions, {'bar': CheckerPublic})
        self.assertFalse(checker.set_permissions)

    def test_no_checker_w_provides_and_permission_protected(self):
        from zope.interface import Interface
        from zope.proxy import getProxiedObject
        class IFoo(Interface):
            def bar(self):
                "bar"
        ctx = self._makeContext()
        proxy = self._callFUT(ctx, provides=IFoo, permission='testing')
        self.assertTrue(getProxiedObject(proxy) is ctx)
        checker = proxy.__Security_checker__
        self.assertEqual(checker.get_permissions, {'bar': 'testing'})
        self.assertFalse(checker.set_permissions)

    def test_w_checker(self):
        from zope.proxy import getProxiedObject
        _CHECKER = object()
        ctx = self._makeContext()
        proxy = self._callFUT(ctx, _CHECKER)
        self.assertTrue(getProxiedObject(proxy) is ctx)
        self.assertTrue(proxy.__Security_checker__ is _CHECKER)

@skipIfNoSecurity
class Test_protectedFactory(unittest.TestCase):

    def _callFUT(self, *args, **kw):
        from zope.component.security import protectedFactory
        return protectedFactory(*args, **kw)

    def test_public_not_already_proxied(self):
        from zope.interface import Interface
        from zope.security.checker import CheckerPublic
        class IFoo(Interface):
            def bar(self):
                "bar"
        class _Factory(object):
            bar = fails_if_called(self)
        protected = self._callFUT(_Factory, IFoo, 'zope.Public')
        self.assertTrue(protected.factory is _Factory)
        foo = protected()
        self.assertEqual(foo.__Security_checker__.get_permissions,
                        {'bar': CheckerPublic})

    def test_nonpublic_already_proxied(self):
        from zope.interface import Interface
        from zope.security.proxy import getTestProxyItems
        class IFoo(Interface):
            def bar(self):
                "bar"
        class _Factory(object):
            __slots__ = ('one',)
            bar = fails_if_called(self)
        protected = self._callFUT(_Factory, IFoo, 'testing')
        self.assertTrue(protected.factory is _Factory)
        foo = protected()
        self.assertEqual(getTestProxyItems(foo), [('bar', 'testing')])

@skipIfNoSecurity
class Test_securityAdapterFactory(unittest.TestCase):

    def _callFUT(self, *args, **kw):
        from zope.component.security import securityAdapterFactory
        return securityAdapterFactory(*args, **kw)

    def test_no_permission_untrusted_no_location(self):
        class _Factory(object):
            pass
        self.assertTrue(self._callFUT(_Factory, None, False, False)
                        is _Factory)

    def test_public_untrusted_no_location(self):
        class _Factory(object):
            pass
        self.assertTrue(self._callFUT(_Factory, 'zope.Public', False, False)
                        is _Factory)

    def test_CheckerPublic_untrusted_no_location(self):
        from zope.security.checker import CheckerPublic
        class _Factory(object):
            pass
        self.assertTrue(self._callFUT(_Factory, CheckerPublic, False, False)
                        is _Factory)

    def test_protected_untrusted_no_location(self):
        from zope.security.adapter import LocatingUntrustedAdapterFactory
        class _Factory(object):
            pass
        proxy = self._callFUT(_Factory, 'testing', False, False)
        self.assertTrue(isinstance(proxy, LocatingUntrustedAdapterFactory))

    def test_no_permission_trusted_no_location(self):
        from zope.security.adapter import LocatingTrustedAdapterFactory
        class _Factory(object):
            pass
        proxy = self._callFUT(_Factory, None, False, True)
        self.assertTrue(isinstance(proxy, LocatingTrustedAdapterFactory))

    def test_public_trusted_no_location(self):
        from zope.security.adapter import LocatingTrustedAdapterFactory
        class _Factory(object):
            pass
        proxy = self._callFUT(_Factory, 'zope.Public', False, True)
        self.assertTrue(isinstance(proxy, LocatingTrustedAdapterFactory))

    def test_CheckerPublic_trusted_no_location(self):
        from zope.security.adapter import LocatingTrustedAdapterFactory
        from zope.security.checker import CheckerPublic
        class _Factory(object):
            pass
        proxy = self._callFUT(_Factory, CheckerPublic, False, True)
        self.assertTrue(isinstance(proxy, LocatingTrustedAdapterFactory))

    def test_protected_trusted_no_location(self):
        from zope.security.adapter import LocatingTrustedAdapterFactory
        class _Factory(object):
            pass
        proxy = self._callFUT(_Factory, 'testing', False, True)
        self.assertTrue(isinstance(proxy, LocatingTrustedAdapterFactory))

    def test_protected_trusted_w_location(self):
        from zope.security.adapter import LocatingTrustedAdapterFactory
        class _Factory(object):
            pass
        proxy = self._callFUT(_Factory, 'testing', True, True)
        self.assertTrue(isinstance(proxy, LocatingTrustedAdapterFactory))
