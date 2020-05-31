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
"""Tests for ZCML directives.
"""
import unittest

from zope.component.tests import fails_if_called
from zope.component.tests import skipIfNoSecurity

class Test_handler(unittest.TestCase):

    def _callFUT(self, *args, **kw):
        from zope.component.zcml import handler
        return handler(*args, **kw)

    def test_uses_configured_site_manager(self):
        from zope.interface.registry import Components
        from zope.component import getSiteManager
        from zope.component.testfiles.components import comp, IApp

        registry = Components()
        def dummy(context=None):
            return registry
        getSiteManager.sethook(dummy)

        try:
            self._callFUT('registerUtility', comp, IApp, u'')
            self.assertTrue(registry.getUtility(IApp) is comp)
        finally:
            getSiteManager.reset()


class Test__rolledUpFactory(unittest.TestCase):

    def _callFUT(self, *args, **kw):
        from zope.component.zcml import _rolledUpFactory
        return _rolledUpFactory(*args, **kw)

    def test_with_one(self):
        _OBJ = object()
        _CREATED = object()
        def _factory(obj):
            return _CREATED
        rolled = self._callFUT([_factory])
        self.assertTrue(rolled.factory is _factory)
        self.assertTrue(rolled(_OBJ) is _CREATED)

    def test_with_multiple(self):
        _OBJ = object()
        _CREATED1 = object()
        _CREATED2 = object()
        _CREATED3 = object()
        def _factory1(obj):
            return _CREATED1
        def _factory2(obj):
            return _CREATED2
        def _factory3(obj):
            return _CREATED3
        rolled = self._callFUT([_factory1, _factory2, _factory3])
        self.assertTrue(rolled.factory is _factory1)
        self.assertTrue(rolled(_OBJ) is _CREATED3)


class Test_adapter(unittest.TestCase):

    def _callFUT(self, *args, **kw):
        from zope.component.zcml import adapter
        return adapter(*args, **kw)

    def test_empty_factory(self):
        from zope.interface import Interface
        from zope.component.zcml import ComponentConfigurationError
        class IFoo(Interface):
            pass
        _cfg_ctx = _makeConfigContext()
        self.assertRaises(ComponentConfigurationError,
                          self._callFUT, _cfg_ctx, [], [Interface], IFoo)

    def test_multiple_factory_multiple_for_(self):
        from zope.interface import Interface
        from zope.component.zcml import ComponentConfigurationError
        class IFoo(Interface):
            pass
        class IBar(Interface):
            pass
        class Foo(object):
            pass
        class Bar(object):
            pass
        _cfg_ctx = _makeConfigContext()
        self.assertRaises(ComponentConfigurationError,
                          self._callFUT, _cfg_ctx, [Foo, Bar],
                                         [Interface, IBar], IFoo)

    def test_no_for__factory_not_adapts(self):
        #@adapter(IFoo)
        class _Factory(object):
            __init__ = fails_if_called(self)
        _cfg_ctx = _makeConfigContext()
        self.assertRaises(TypeError, self._callFUT, _cfg_ctx, [_Factory])

    def test_no_name(self):
        from zope.interface import Interface
        class IFoo(Interface):
            pass
        class IBar(Interface):
            pass
        from zope.component import adapter, named
        from zope.interface import implementer
        @adapter(IFoo)
        @implementer(IBar)
        @named('bar')
        class _Factory(object):
            __init__ = fails_if_called(self)
        _cfg_ctx = _makeConfigContext()
        self._callFUT(_cfg_ctx, [_Factory])
        # Register the adapter
        action =_cfg_ctx._actions[0][1]
        self.assertEqual(action['args'][4], 'bar')

    def test_no_for__factory_adapts_no_provides_factory_not_implements(self):
        from zope.interface import Interface
        from zope.component._declaration import adapter
        @adapter(Interface)
        class _Factory(object):
            __init__ = fails_if_called(self)
        _cfg_ctx = _makeConfigContext()
        self.assertRaises(TypeError, self._callFUT, _cfg_ctx, [_Factory])

    def test_multiple_factory_single_for__w_name(self):
        from zope.interface import Interface
        from zope.component.interface import provideInterface
        from zope.component.zcml import handler
        class IFoo(Interface):
            pass
        class Foo(object):
            pass
        class Bar(object):
            pass
        _cfg_ctx = _makeConfigContext()
        self._callFUT(_cfg_ctx, [Foo, Bar], IFoo, [Interface], name='test')
        self.assertEqual(len(_cfg_ctx._actions), 3)
        self.assertEqual(_cfg_ctx._actions[0][0], ())
        # Register the adapter
        action =_cfg_ctx._actions[0][1]
        self.assertEqual(action['callable'], handler)
        self.assertEqual(action['discriminator'],
                         ('adapter', (Interface,), IFoo, 'test'))
        self.assertEqual(action['args'][0], 'registerAdapter')
        self.assertEqual(action['args'][1].factory, Foo) #rolled up
        self.assertEqual(action['args'][2], (Interface,))
        self.assertEqual(action['args'][3], IFoo)
        self.assertEqual(action['args'][4], 'test')
        self.assertEqual(action['args'][5], 'TESTING')
        # Register the provided interface
        self.assertEqual(_cfg_ctx._actions[1][0], ())
        action =_cfg_ctx._actions[1][1]
        self.assertEqual(action['callable'], provideInterface)
        self.assertEqual(action['discriminator'], None)
        self.assertEqual(action['args'], ('', IFoo))
        # Register the required interface(s)
        self.assertEqual(_cfg_ctx._actions[2][0], ())
        action =_cfg_ctx._actions[2][1]
        self.assertEqual(action['callable'], provideInterface)
        self.assertEqual(action['discriminator'], None)
        self.assertEqual(action['args'], ('', Interface))

    @skipIfNoSecurity
    def test_single_factory_single_for_w_permission(self):
        from zope.interface import Interface
        from zope.security.adapter import LocatingUntrustedAdapterFactory
        from zope.component.zcml import handler
        class IFoo(Interface):
            pass
        class Foo(object):
            pass
        _cfg_ctx = _makeConfigContext()
        self._callFUT(_cfg_ctx, [Foo], IFoo, [Interface], permission='testing')
        self.assertEqual(len(_cfg_ctx._actions), 3)
        self.assertEqual(_cfg_ctx._actions[0][0], ())
        # Register the adapter
        action =_cfg_ctx._actions[0][1]
        self.assertEqual(action['callable'], handler)
        self.assertEqual(action['discriminator'],
                         ('adapter', (Interface,), IFoo, ''))
        self.assertEqual(action['args'][0], 'registerAdapter')
        factory_proxy = action['args'][1]
        # Foo wraped by 'protected_factory' plus
        # 'LocatingUntrustedAdapterFactory'
        self.assertTrue(isinstance(factory_proxy,
                        LocatingUntrustedAdapterFactory))
        self.assertTrue(factory_proxy.factory.factory is Foo)
        self.assertEqual(action['args'][2], (Interface,))
        self.assertEqual(action['args'][3], IFoo)
        self.assertEqual(action['args'][4], '')
        self.assertEqual(action['args'][5], 'TESTING')

    @skipIfNoSecurity
    def test_single_factory_single_for_w_locate_no_permission(self):
        from zope.interface import Interface
        from zope.security.adapter import LocatingUntrustedAdapterFactory
        from zope.component.zcml import handler
        class IFoo(Interface):
            pass
        class Foo(object):
            pass
        _cfg_ctx = _makeConfigContext()
        self._callFUT(_cfg_ctx, [Foo], IFoo, [Interface], locate=True)
        self.assertEqual(len(_cfg_ctx._actions), 3)
        self.assertEqual(_cfg_ctx._actions[0][0], ())
        # Register the adapter
        action =_cfg_ctx._actions[0][1]
        self.assertEqual(action['callable'], handler)
        self.assertEqual(action['discriminator'],
                         ('adapter', (Interface,), IFoo, ''))
        self.assertEqual(action['args'][0], 'registerAdapter')
        factory_proxy = action['args'][1]
        # Foo wraped by 'LocatingUntrustedAdapterFactory'
        self.assertTrue(isinstance(factory_proxy,
                        LocatingUntrustedAdapterFactory))
        self.assertTrue(factory_proxy.factory is Foo)
        self.assertEqual(action['args'][2], (Interface,))
        self.assertEqual(action['args'][3], IFoo)
        self.assertEqual(action['args'][4], '')
        self.assertEqual(action['args'][5], 'TESTING')

    @skipIfNoSecurity
    def test_single_factory_single_for_w_trusted_no_permission(self):
        from zope.interface import Interface
        from zope.security.adapter import TrustedAdapterFactory
        from zope.component.zcml import handler
        class IFoo(Interface):
            pass
        class Foo(object):
            pass
        _cfg_ctx = _makeConfigContext()
        self._callFUT(_cfg_ctx, [Foo], IFoo, [Interface], trusted=True)
        self.assertEqual(len(_cfg_ctx._actions), 3)
        self.assertEqual(_cfg_ctx._actions[0][0], ())
        # Register the adapter
        action =_cfg_ctx._actions[0][1]
        self.assertEqual(action['callable'], handler)
        self.assertEqual(action['discriminator'],
                         ('adapter', (Interface,), IFoo, ''))
        self.assertEqual(action['args'][0], 'registerAdapter')
        factory_proxy = action['args'][1]
        # Foo wraped by 'LocatingUntrustedAdapterFactory'
        self.assertTrue(isinstance(factory_proxy, TrustedAdapterFactory))
        self.assertTrue(factory_proxy.factory is Foo)
        self.assertEqual(action['args'][2], (Interface,))
        self.assertEqual(action['args'][3], IFoo)
        self.assertEqual(action['args'][4], '')
        self.assertEqual(action['args'][5], 'TESTING')

    def test_no_for__no_provides_factory_adapts_factory_implements(self):
        from zope.interface import Interface
        from zope.interface import implementer
        from zope.component._declaration import adapter
        from zope.component.zcml import handler
        class IFoo(Interface):
            pass
        @adapter(Interface)
        @implementer(IFoo)
        class _Factory(object):
            __init__ = fails_if_called(self)
        _cfg_ctx = _makeConfigContext()
        self._callFUT(_cfg_ctx, [_Factory])
        self.assertEqual(len(_cfg_ctx._actions), 3)
        self.assertEqual(_cfg_ctx._actions[0][0], ())
        # Register the adapter
        action =_cfg_ctx._actions[0][1]
        self.assertEqual(action['callable'], handler)
        self.assertEqual(action['discriminator'],
                         ('adapter', (Interface,), IFoo, ''))
        self.assertEqual(action['args'],
                         ('registerAdapter', _Factory, (Interface,), IFoo,
                          '', 'TESTING'))

class Test_zcml_functional(unittest.TestCase):
    # These mimic the snippets in the zcml.rst doctests

    def setUp(self):
        from zope.component.tests.examples import clearZCML
        clearZCML()
    tearDown = setUp

    def _runSnippet(self, snippet):
        from zope.configuration import xmlconfig
        template = """\
        <configure xmlns='http://namespaces.zope.org/zope'
                   i18n_domain="zope">
           <include package="zope.component" file="meta.zcml" />
           %s
        </configure>""" % snippet
        xmlconfig.string(template)


    @skipIfNoSecurity
    def test_with_proxy_factory_public_permission(self):
        # Using the public permission doesn't give you a location proxy
        from zope.proxy import isProxy
        from zope.security.proxy import removeSecurityProxy
        from zope.component.testfiles.components import Content
        from zope.component.testfiles.adapter import I1, A1
        from zope.security.checker import ProxyFactory

        self._runSnippet('''
            <adapter
            for="zope.component.testfiles.components.IContent"
            provides="zope.component.testfiles.adapter.I1"
            factory="zope.component.testfiles.adapter.A1"
            permission="zope.Public"
            trusted="yes"
             />''')
        ob = Content()
        p = ProxyFactory(ob)

        a = I1(p)

        self.assertTrue(isProxy(a))

        self.assertTrue(type(removeSecurityProxy(a)) is A1)

    @skipIfNoSecurity
    def test_located_proxy_factory(self):
        # Passing locate results in a security proxy around a location proxy
        from zope.proxy import isProxy
        from zope.security.proxy import removeSecurityProxy
        from zope.component.testfiles.components import Content
        from zope.component.testfiles.adapter import I1
        from zope.security.checker import ProxyFactory
        from zope.location.location import LocationProxy

        self._runSnippet('''
        <adapter
          for="zope.component.testfiles.components.IContent"
          provides="zope.component.testfiles.adapter.I1"
          factory="zope.component.testfiles.adapter.A1"
          trusted="yes"
          locate="yes"
          />
        ''')
        ob = Content()
        p = ProxyFactory(ob)
        a = I1(p)

        self.assertTrue(isProxy(a))

        self.assertTrue(type(removeSecurityProxy(a)) is LocationProxy)

class Test_subscriber(unittest.TestCase):

    def _callFUT(self, *args, **kw):
        from zope.component.zcml import subscriber
        return subscriber(*args, **kw)

    def test_no_factory_no_handler(self):
        from zope.interface import Interface
        _cfg_ctx = _makeConfigContext()
        self.assertRaises(TypeError,
                          self._callFUT, _cfg_ctx, (Interface,))

    def test_no_factory_w_handler_w_provides(self):
        from zope.interface import Interface
        class IFoo(Interface):
            pass
        _handler = fails_if_called(self)
        _cfg_ctx = _makeConfigContext()
        self.assertRaises(TypeError,
                          self._callFUT, _cfg_ctx, (Interface,),
                                         handler=_handler, provides=IFoo)

    def test_w_factory_w_handler(self):
        from zope.interface import Interface
        class Foo(object):
            pass
        _handler = fails_if_called(self)
        _cfg_ctx = _makeConfigContext()
        self.assertRaises(TypeError,
                          self._callFUT, _cfg_ctx, (Interface,), Foo,
                                         handler=_handler)

    def test_w_factory_no_provides(self):
        from zope.interface import Interface
        class Foo(object):
            pass
        _cfg_ctx = _makeConfigContext()
        self.assertRaises(TypeError,
                          self._callFUT, _cfg_ctx, (Interface,), Foo)

    def test_w_factory_w_provides_no_for_factory_wo_adapter(self):
        from zope.interface import Interface
        class IFoo(Interface):
            pass
        class Foo(object):
            pass
        _cfg_ctx = _makeConfigContext()
        self.assertRaises(TypeError,
                          self._callFUT, _cfg_ctx,
                                         factory=Foo, provides=IFoo)

    def test_no_factory_w_handler_no_provides(self):
        from zope.interface import Interface
        from zope.component.interface import provideInterface
        from zope.component.zcml import handler
        _handler = fails_if_called(self)
        _cfg_ctx = _makeConfigContext()
        self._callFUT(_cfg_ctx, (Interface,), handler=_handler)
        self.assertEqual(len(_cfg_ctx._actions), 2)
        self.assertEqual(_cfg_ctx._actions[0][0], ())
        # Register the adapter
        action =_cfg_ctx._actions[0][1]
        self.assertEqual(action['callable'], handler)
        self.assertEqual(action['discriminator'], None)
        self.assertEqual(action['args'][0], 'registerHandler')
        self.assertEqual(action['args'][1], _handler)
        self.assertEqual(action['args'][2], (Interface,))
        self.assertEqual(action['args'][3], '')
        self.assertEqual(action['args'][4], 'TESTING')
        # Register the required interface(s)
        self.assertEqual(_cfg_ctx._actions[1][0], ())
        action =_cfg_ctx._actions[1][1]
        self.assertEqual(action['callable'], provideInterface)
        self.assertEqual(action['discriminator'], None)
        self.assertEqual(action['args'], ('', Interface))

    def test_w_factory_w_provides(self):
        from zope.interface import Interface
        from zope.component.interface import provideInterface
        from zope.component.zcml import handler
        class IFoo(Interface):
            pass
        class Foo(object):
            pass
        _handler = fails_if_called(self)
        _cfg_ctx = _makeConfigContext()
        self._callFUT(_cfg_ctx, (Interface,), Foo, provides=IFoo)
        self.assertEqual(len(_cfg_ctx._actions), 3)
        self.assertEqual(_cfg_ctx._actions[0][0], ())
        # Register the adapter
        action =_cfg_ctx._actions[0][1]
        self.assertEqual(action['callable'], handler)
        self.assertEqual(action['discriminator'], None)
        self.assertEqual(action['args'][0], 'registerSubscriptionAdapter')
        self.assertEqual(action['args'][1], Foo)
        self.assertEqual(action['args'][2], (Interface,))
        self.assertEqual(action['args'][3], IFoo)
        self.assertEqual(action['args'][4], '')
        self.assertEqual(action['args'][5], 'TESTING')
        # Register the provided interface
        self.assertEqual(_cfg_ctx._actions[1][0], ())
        action =_cfg_ctx._actions[1][1]
        self.assertEqual(action['callable'], provideInterface)
        self.assertEqual(action['discriminator'], None)
        self.assertEqual(action['args'], ('', IFoo))
        # Register the required interface(s)
        self.assertEqual(_cfg_ctx._actions[2][0], ())
        action =_cfg_ctx._actions[2][1]
        self.assertEqual(action['callable'], provideInterface)
        self.assertEqual(action['discriminator'], None)
        self.assertEqual(action['args'], ('', Interface))

    @skipIfNoSecurity
    def test_w_factory_w_provides_w_permission(self):
        from zope.interface import Interface
        from zope.security.adapter import LocatingUntrustedAdapterFactory
        from zope.component.interface import provideInterface
        from zope.component.zcml import handler
        class IFoo(Interface):
            pass
        class Foo(object):
            pass
        _cfg_ctx = _makeConfigContext()
        self._callFUT(_cfg_ctx, (Interface,), Foo,
                      provides=IFoo, permission='testing')
        self.assertEqual(len(_cfg_ctx._actions), 3)
        self.assertEqual(_cfg_ctx._actions[0][0], ())
        # Register the adapter
        action =_cfg_ctx._actions[0][1]
        self.assertEqual(action['callable'], handler)
        self.assertEqual(action['discriminator'], None)
        self.assertEqual(action['args'][0], 'registerSubscriptionAdapter')
        factory_proxy = action['args'][1]
        # Foo wraped by 'protected_factory' plus
        # 'LocatingUntrustedAdapterFactory'
        self.assertTrue(isinstance(factory_proxy,
                        LocatingUntrustedAdapterFactory))
        self.assertTrue(factory_proxy.factory.factory is Foo)
        self.assertEqual(action['args'][2], (Interface,))
        self.assertEqual(action['args'][3], IFoo)
        self.assertEqual(action['args'][4], '')
        self.assertEqual(action['args'][5], 'TESTING')
        # Register the provided interface
        self.assertEqual(_cfg_ctx._actions[1][0], ())
        action =_cfg_ctx._actions[1][1]
        self.assertEqual(action['callable'], provideInterface)
        self.assertEqual(action['discriminator'], None)
        self.assertEqual(action['args'], ('', IFoo))
        # Register the required interface(s)
        self.assertEqual(_cfg_ctx._actions[2][0], ())
        action =_cfg_ctx._actions[2][1]
        self.assertEqual(action['callable'], provideInterface)
        self.assertEqual(action['discriminator'], None)
        self.assertEqual(action['args'], ('', Interface))

    @skipIfNoSecurity
    def test_w_factory_w_provides_wo_permission_w_locate(self):
        from zope.interface import Interface
        from zope.security.adapter import LocatingUntrustedAdapterFactory
        from zope.component.interface import provideInterface
        from zope.component.zcml import handler
        class IFoo(Interface):
            pass
        class Foo(object):
            pass
        _cfg_ctx = _makeConfigContext()
        self._callFUT(_cfg_ctx, (Interface,), Foo, provides=IFoo, locate=True)
        self.assertEqual(len(_cfg_ctx._actions), 3)
        self.assertEqual(_cfg_ctx._actions[0][0], ())
        # Register the adapter
        action =_cfg_ctx._actions[0][1]
        self.assertEqual(action['callable'], handler)
        self.assertEqual(action['discriminator'], None)
        self.assertEqual(action['args'][0], 'registerSubscriptionAdapter')
        factory_proxy = action['args'][1]
        # Foo wraped by 'protected_factory' plus
        # 'LocatingUntrustedAdapterFactory'
        self.assertTrue(isinstance(factory_proxy,
                        LocatingUntrustedAdapterFactory))
        self.assertTrue(factory_proxy.factory is Foo)
        self.assertEqual(action['args'][2], (Interface,))
        self.assertEqual(action['args'][3], IFoo)
        self.assertEqual(action['args'][4], '')
        self.assertEqual(action['args'][5], 'TESTING')
        # Register the provided interface
        self.assertEqual(_cfg_ctx._actions[1][0], ())
        action =_cfg_ctx._actions[1][1]
        self.assertEqual(action['callable'], provideInterface)
        self.assertEqual(action['discriminator'], None)
        self.assertEqual(action['args'], ('', IFoo))
        # Register the required interface(s)
        self.assertEqual(_cfg_ctx._actions[2][0], ())
        action =_cfg_ctx._actions[2][1]
        self.assertEqual(action['callable'], provideInterface)
        self.assertEqual(action['discriminator'], None)
        self.assertEqual(action['args'], ('', Interface))

    @skipIfNoSecurity
    def test_w_factory_w_provides_wo_permission_w_trusted(self):
        from zope.interface import Interface
        from zope.security.adapter import TrustedAdapterFactory
        from zope.component.interface import provideInterface
        from zope.component.zcml import handler
        class IFoo(Interface):
            pass
        class Foo(object):
            pass
        _cfg_ctx = _makeConfigContext()
        self._callFUT(_cfg_ctx, (Interface,), Foo, provides=IFoo, trusted=True)
        self.assertEqual(len(_cfg_ctx._actions), 3)
        self.assertEqual(_cfg_ctx._actions[0][0], ())
        # Register the adapter
        action =_cfg_ctx._actions[0][1]
        self.assertEqual(action['callable'], handler)
        self.assertEqual(action['discriminator'], None)
        self.assertEqual(action['args'][0], 'registerSubscriptionAdapter')
        factory_proxy = action['args'][1]
        # Foo wraped by 'protected_factory' plus
        # 'TrustedAdapterFactory'
        self.assertTrue(isinstance(factory_proxy,
                        TrustedAdapterFactory))
        self.assertTrue(factory_proxy.factory is Foo)
        self.assertEqual(action['args'][2], (Interface,))
        self.assertEqual(action['args'][3], IFoo)
        self.assertEqual(action['args'][4], '')
        self.assertEqual(action['args'][5], 'TESTING')
        # Register the provided interface
        self.assertEqual(_cfg_ctx._actions[1][0], ())
        action =_cfg_ctx._actions[1][1]
        self.assertEqual(action['callable'], provideInterface)
        self.assertEqual(action['discriminator'], None)
        self.assertEqual(action['args'], ('', IFoo))
        # Register the required interface(s)
        self.assertEqual(_cfg_ctx._actions[2][0], ())
        action =_cfg_ctx._actions[2][1]
        self.assertEqual(action['callable'], provideInterface)
        self.assertEqual(action['discriminator'], None)
        self.assertEqual(action['args'], ('', Interface))


class Test_utility(unittest.TestCase):

    def _callFUT(self, *args, **kw):
        from zope.component.zcml import utility
        return utility(*args, **kw)

    def test_w_factory_w_component(self):
        class _Factory(object):
            pass
        _COMPONENT = object
        _cfg_ctx = _makeConfigContext()
        self.assertRaises(TypeError, self._callFUT, _cfg_ctx,
                                         factory=_Factory,
                                         component=_COMPONENT)

    def test_w_factory_wo_provides_factory_no_implements(self):
        class _Factory(object):
            pass
        _cfg_ctx = _makeConfigContext()
        self.assertRaises(TypeError,
                          self._callFUT, _cfg_ctx, factory=_Factory)

    def test_w_component_wo_provides_component_no_provides(self):
        _COMPONENT = object
        _cfg_ctx = _makeConfigContext()
        self.assertRaises(TypeError,
                          self._callFUT, _cfg_ctx, component=_COMPONENT)

    def test_w_factory_w_provides(self):
        from zope.interface import Interface
        from zope.component.interface import provideInterface
        from zope.component.zcml import handler
        class IFoo(Interface):
            pass
        class Foo(object):
            pass
        _cfg_ctx = _makeConfigContext()
        self._callFUT(_cfg_ctx, factory=Foo, provides=IFoo)
        self.assertEqual(len(_cfg_ctx._actions), 2)
        self.assertEqual(_cfg_ctx._actions[0][0], ())
        # Register the utility
        action =_cfg_ctx._actions[0][1]
        self.assertEqual(action['callable'], handler)
        self.assertEqual(action['discriminator'], ('utility', IFoo, ''))
        self.assertEqual(action['args'][0], 'registerUtility')
        self.assertEqual(action['args'][1], None)
        self.assertEqual(action['args'][2], IFoo)
        self.assertEqual(action['args'][3], '')
        self.assertEqual(action['args'][4], 'TESTING')
        self.assertEqual(action['kw'], {'factory': Foo})
        # Register the provided interface
        self.assertEqual(_cfg_ctx._actions[1][0], ())
        action =_cfg_ctx._actions[1][1]
        self.assertEqual(action['callable'], provideInterface)
        self.assertEqual(action['discriminator'], None)
        self.assertEqual(action['args'], ('', IFoo))

    def test_w_factory_wo_provides_factory_implements(self):
        from zope.interface import Interface
        from zope.interface import implementer
        from zope.component.interface import provideInterface
        from zope.component.zcml import handler
        class IFoo(Interface):
            pass
        @implementer(IFoo)
        class Foo(object):
            pass
        _cfg_ctx = _makeConfigContext()
        self._callFUT(_cfg_ctx, factory=Foo)
        self.assertEqual(len(_cfg_ctx._actions), 2)
        self.assertEqual(_cfg_ctx._actions[0][0], ())
        # Register the utility
        action =_cfg_ctx._actions[0][1]
        self.assertEqual(action['callable'], handler)
        self.assertEqual(action['discriminator'], ('utility', IFoo, ''))
        self.assertEqual(action['args'][0], 'registerUtility')
        self.assertEqual(action['args'][1], None)
        self.assertEqual(action['args'][2], IFoo)
        self.assertEqual(action['args'][3], '')
        self.assertEqual(action['args'][4], 'TESTING')
        self.assertEqual(action['kw'], {'factory': Foo})
        # Register the provided interface
        self.assertEqual(_cfg_ctx._actions[1][0], ())
        action =_cfg_ctx._actions[1][1]
        self.assertEqual(action['callable'], provideInterface)
        self.assertEqual(action['discriminator'], None)
        self.assertEqual(action['args'], ('', IFoo))

    def test_w_component_w_provides_w_name(self):
        from zope.interface import Interface
        from zope.component.interface import provideInterface
        from zope.component.zcml import handler
        class IFoo(Interface):
            pass
        _COMPONENT = object()
        _cfg_ctx = _makeConfigContext()
        self._callFUT(_cfg_ctx, component=_COMPONENT,
                      name='test', provides=IFoo)
        self.assertEqual(len(_cfg_ctx._actions), 2)
        self.assertEqual(_cfg_ctx._actions[0][0], ())
        # Register the utility
        action =_cfg_ctx._actions[0][1]
        self.assertEqual(action['callable'], handler)
        self.assertEqual(action['discriminator'], ('utility', IFoo, 'test'))
        self.assertEqual(action['args'][0], 'registerUtility')
        self.assertEqual(action['args'][1], _COMPONENT)
        self.assertEqual(action['args'][2], IFoo)
        self.assertEqual(action['args'][3], 'test')
        self.assertEqual(action['args'][4], 'TESTING')
        # Register the provided interface
        self.assertEqual(_cfg_ctx._actions[1][0], ())
        action =_cfg_ctx._actions[1][1]
        self.assertEqual(action['callable'], provideInterface)
        self.assertEqual(action['discriminator'], None)
        self.assertEqual(action['args'], ('', IFoo))

    def test_w_component_wo_provides_wo_name(self):
        from zope.interface import Interface, implementer, named
        from zope.component.zcml import handler
        class IFoo(Interface):
            pass
        @implementer(IFoo)
        @named('foo')
        class Foo(object):
            pass
        foo = Foo()
        _cfg_ctx = _makeConfigContext()
        self._callFUT(_cfg_ctx, component=foo)
        action =_cfg_ctx._actions[0][1]
        self.assertEqual(action['args'][1], foo)
        self.assertEqual(action['args'][2], IFoo)
        self.assertEqual(action['args'][3], 'foo')

    def test_w_component_wo_provides_component_provides(self):
        from zope.interface import Interface
        from zope.interface import directlyProvides
        from zope.component.interface import provideInterface
        from zope.component.zcml import handler
        class IFoo(Interface):
            pass
        class Foo(object):
            pass
        _COMPONENT = Foo()
        directlyProvides(_COMPONENT, IFoo)
        _cfg_ctx = _makeConfigContext()
        self._callFUT(_cfg_ctx, component=_COMPONENT)
        self.assertEqual(len(_cfg_ctx._actions), 2)
        self.assertEqual(_cfg_ctx._actions[0][0], ())
        # Register the utility
        action =_cfg_ctx._actions[0][1]
        self.assertEqual(action['callable'], handler)
        self.assertEqual(action['discriminator'], ('utility', IFoo, ''))
        self.assertEqual(action['args'][0], 'registerUtility')
        self.assertEqual(action['args'][1], _COMPONENT)
        self.assertEqual(action['args'][2], IFoo)
        self.assertEqual(action['args'][3], '')
        self.assertEqual(action['args'][4], 'TESTING')
        # Register the provided interface
        self.assertEqual(_cfg_ctx._actions[1][0], ())
        action =_cfg_ctx._actions[1][1]
        self.assertEqual(action['callable'], provideInterface)
        self.assertEqual(action['discriminator'], None)
        self.assertEqual(action['args'], ('', IFoo))

    @skipIfNoSecurity
    def test_w_component_w_provides_w_permission(self):
        from zope.interface import Interface
        from zope.proxy import removeAllProxies
        from zope.component.interface import provideInterface
        from zope.component.security import PermissionProxy
        from zope.component.zcml import handler
        class IFoo(Interface):
            def bar(self):
                "bar"
        class Foo(object):
            bar = fails_if_called(self)
        _COMPONENT = Foo()
        _cfg_ctx = _makeConfigContext()
        self._callFUT(_cfg_ctx, component=_COMPONENT,
                                provides=IFoo, permission='testing')
        self.assertEqual(len(_cfg_ctx._actions), 2)
        self.assertEqual(_cfg_ctx._actions[0][0], ())
        # Register the utility
        action =_cfg_ctx._actions[0][1]
        self.assertEqual(action['callable'], handler)
        self.assertEqual(action['discriminator'], ('utility', IFoo, ''))
        self.assertEqual(action['args'][0], 'registerUtility')
        component_proxy = action['args'][1]
        self.assertTrue(isinstance(component_proxy, PermissionProxy))
        self.assertTrue(removeAllProxies(component_proxy) is _COMPONENT)
        self.assertEqual(component_proxy.__Security_checker__.get_permissions,
                         {'bar': 'testing'})
        self.assertEqual(action['args'][2], IFoo)
        self.assertEqual(action['args'][3], '')
        self.assertEqual(action['args'][4], 'TESTING')
        # Register the provided interface
        self.assertEqual(_cfg_ctx._actions[1][0], ())
        action =_cfg_ctx._actions[1][1]
        self.assertEqual(action['callable'], provideInterface)
        self.assertEqual(action['discriminator'], None)
        self.assertEqual(action['args'], ('', IFoo))

class Test_interface(unittest.TestCase):

    def _callFUT(self, *args, **kw):
        from zope.component.zcml import interface
        return interface(*args, **kw)

    def test_wo_name_wo_type(self):
        from zope.interface import Interface
        from zope.component.interface import provideInterface
        class IFoo(Interface):
            pass
        _cfg_ctx = _makeConfigContext()
        self._callFUT(_cfg_ctx, IFoo)
        self.assertEqual(len(_cfg_ctx._actions), 1)
        self.assertEqual(_cfg_ctx._actions[0][0], ())
        action =_cfg_ctx._actions[0][1]
        self.assertEqual(action['callable'], provideInterface)
        self.assertEqual(action['discriminator'], None)
        self.assertEqual(action['args'], ('', IFoo, None))

    def test_w_name_w_type(self):
        from zope.interface import Interface
        from zope.component.interface import provideInterface
        class IFoo(Interface):
            pass
        class IBar(Interface):
            pass
        _cfg_ctx = _makeConfigContext()
        self._callFUT(_cfg_ctx, IFoo, name='foo', type=IBar)
        self.assertEqual(len(_cfg_ctx._actions), 1)
        self.assertEqual(_cfg_ctx._actions[0][0], ())
        action =_cfg_ctx._actions[0][1]
        self.assertEqual(action['callable'], provideInterface)
        self.assertEqual(action['discriminator'], None)
        self.assertEqual(action['args'], ('foo', IFoo, IBar))


class Test_view(unittest.TestCase):

    def _callFUT(self, *args, **kw):
        from zope.component.zcml import view
        return view(*args, **kw)

    def test_w_allowed_interface_wo_permission(self):
        from zope.interface import Interface
        from zope.component.zcml import ComponentConfigurationError
        class IViewType(Interface):
            pass
        class IView(Interface):
            def foo():
                "foo"
            def bar():
                "bar"
        class _View(object):
            __init__ = fails_if_called(self)
            foo = fails_if_called(self)
            bar = fails_if_called(self)
        _cfg_ctx = _makeConfigContext()
        self.assertRaises(ComponentConfigurationError,
                          self._callFUT, _cfg_ctx, (_View,), IViewType, '',
                                         for_=(Interface, Interface),
                                         allowed_interface=IView)

    def test_w_allowed_attributes_wo_permission(self):
        from zope.interface import Interface
        from zope.component.zcml import ComponentConfigurationError
        class IViewType(Interface):
            pass
        class _View(object):
            __init__ = fails_if_called(self)
            foo = fails_if_called(self)
            bar = fails_if_called(self)
        _cfg_ctx = _makeConfigContext()
        self.assertRaises(ComponentConfigurationError,
                          self._callFUT, _cfg_ctx, (_View,), IViewType, '',
                                         for_=(Interface, Interface),
                                         allowed_attributes=('foo', 'bar'))

    def test_w_factory_as_empty(self):
        from zope.interface import Interface
        from zope.component.zcml import ComponentConfigurationError
        class IViewType(Interface):
            pass
        _cfg_ctx = _makeConfigContext()
        self.assertRaises(ComponentConfigurationError,
                          self._callFUT, _cfg_ctx, (), IViewType, '',
                                         for_=(Interface, Interface))

    def test_w_multiple_factory_multiple_for_(self):
        from zope.interface import Interface
        from zope.component.zcml import ComponentConfigurationError
        class IViewType(Interface):
            pass
        class Foo(object):
            pass
        class Bar(object):
            pass
        _cfg_ctx = _makeConfigContext()
        self.assertRaises(ComponentConfigurationError,
                          self._callFUT, _cfg_ctx, (Foo, Bar), IViewType, '',
                                         for_=(Interface, Interface))

    def test_w_for__as_empty(self):
        from zope.interface import Interface
        from zope.component.zcml import ComponentConfigurationError
        class IViewType(Interface):
            pass
        class _View(object):
            __init__ = fails_if_called(self)
        _cfg_ctx = _makeConfigContext()
        self.assertRaises(ComponentConfigurationError,
                          self._callFUT, _cfg_ctx, (_View,), IViewType, '',
                                         for_=())

    def test_w_single_factory_single_for__wo_permission_w_name(self):
        from zope.interface import Interface
        from zope.component.zcml import handler
        from zope.component.interface import provideInterface
        class IViewType(Interface):
            pass
        class _View(object):
            __init__ = fails_if_called(self)
        _cfg_ctx = _makeConfigContext()
        self._callFUT(_cfg_ctx, (_View,), IViewType, 'test', for_=(Interface,))
        self.assertEqual(len(_cfg_ctx._actions), 4)
        self.assertEqual(_cfg_ctx._actions[0][0], ())
        # Register the adapter
        action =_cfg_ctx._actions[0][1]
        self.assertEqual(action['callable'], handler)
        self.assertEqual(action['discriminator'],
                         ('view', (Interface, IViewType), 'test', Interface))
        self.assertEqual(action['args'][0], 'registerAdapter')
        self.assertEqual(action['args'][1], _View)
        self.assertEqual(action['args'][2], (Interface, IViewType))
        self.assertEqual(action['args'][3], Interface)
        self.assertEqual(action['args'][4], 'test')
        self.assertEqual(action['args'][5], 'TESTING')
        # Register the provided interface
        self.assertEqual(_cfg_ctx._actions[1][0], ())
        action =_cfg_ctx._actions[1][1]
        self.assertEqual(action['callable'], provideInterface)
        self.assertEqual(action['discriminator'], None)
        self.assertEqual(action['args'], ('', Interface))
        # Register the required interface(s)
        self.assertEqual(_cfg_ctx._actions[2][0], ())
        action =_cfg_ctx._actions[2][1]
        self.assertEqual(action['callable'], provideInterface)
        self.assertEqual(action['discriminator'], None)
        self.assertEqual(action['args'], ('', Interface))
        self.assertEqual(_cfg_ctx._actions[3][0], ())
        action =_cfg_ctx._actions[3][1]
        self.assertEqual(action['callable'], provideInterface)
        self.assertEqual(action['discriminator'], None)
        self.assertEqual(action['args'], ('', IViewType))

    def test_w_multiple_factory_single_for__wo_permission(self):
        from zope.interface import Interface
        from zope.component.zcml import handler
        class IViewType(Interface):
            pass
        class _View(object):
            def __init__(self, context):
                self.context = context
        class _View2(object):
            def __init__(self, context, request):
                self.context = context
                self.request = request
        _cfg_ctx = _makeConfigContext()
        self._callFUT(_cfg_ctx, [_View, _View2], IViewType, '',
                      for_=(Interface,))
        self.assertEqual(_cfg_ctx._actions[0][0], ())
        # Register the adapter
        action =_cfg_ctx._actions[0][1]
        self.assertEqual(action['callable'], handler)
        self.assertEqual(action['discriminator'],
                         ('view', (Interface, IViewType), '', Interface))
        self.assertEqual(action['args'][0], 'registerAdapter')
        factory = action['args'][1]
        self.assertTrue(factory.factory is _View)
        context = object()
        request = object()
        view = factory(context, request)
        self.assertTrue(isinstance(view, _View2))
        self.assertTrue(view.request is request)
        self.assertTrue(isinstance(view.context, _View))
        self.assertTrue(view.context.context is context)
        self.assertEqual(action['args'][2], (Interface, IViewType))
        self.assertEqual(action['args'][3], Interface)
        self.assertEqual(action['args'][4], '')
        self.assertEqual(action['args'][5], 'TESTING')

    @skipIfNoSecurity
    def test_w_single_factory_single_for__w_permission(self):
        from zope.interface import Interface
        from zope.component.zcml import handler
        class IViewType(Interface):
            pass
        class _View(object):
            def __init__(self, context, request):
                self.context = context
                self.request = request
        _cfg_ctx = _makeConfigContext()
        self._callFUT(_cfg_ctx, [_View], IViewType, '', for_=(Interface,),
                      permission='testing')
        self.assertEqual(_cfg_ctx._actions[0][0], ())
        # Register the adapter
        action =_cfg_ctx._actions[0][1]
        self.assertEqual(action['callable'], handler)
        self.assertEqual(action['discriminator'],
                         ('view', (Interface, IViewType), '', Interface))
        self.assertEqual(action['args'][0], 'registerAdapter')
        factory = action['args'][1]
        context = object()
        request = object()
        view = factory(context, request)
        self.assertTrue(view.context is context)
        self.assertTrue(view.request is request)
        self.assertTrue(factory.factory is _View)
        self.assertEqual(action['args'][2], (Interface, IViewType))
        self.assertEqual(action['args'][3], Interface)
        self.assertEqual(action['args'][4], '')
        self.assertEqual(action['args'][5], 'TESTING')

    @skipIfNoSecurity
    def test_w_single_factory_single_for__w_permission_and_allowed_attrs(self):
        from zope.interface import Interface
        from zope.component.zcml import handler
        class IViewType(Interface):
            pass
        class _View(object):
            __init__ = fails_if_called(self)
            bar = fails_if_called(self)
        _cfg_ctx = _makeConfigContext()
        self._callFUT(_cfg_ctx, [_View], IViewType, '', for_=(Interface,),
                      permission='testing', allowed_attributes=('bar',))
        self.assertEqual(_cfg_ctx._actions[0][0], ())
        # Register the adapter
        action =_cfg_ctx._actions[0][1]
        self.assertEqual(action['callable'], handler)
        self.assertEqual(action['discriminator'],
                         ('view', (Interface, IViewType), '', Interface))
        self.assertEqual(action['args'][0], 'registerAdapter')
        factory = action['args'][1]
        checker = factory.checker
        self.assertEqual(checker.get_permissions, {'bar': 'testing'})

    @skipIfNoSecurity
    def test_w_single_factory_single_for__w_permission_and_allowed_iface(self):
        from zope.interface import Interface
        from zope.component.zcml import handler
        class IViewType(Interface):
            def bar(self):
                "bar"
        class _View(object):
            __init__ = fails_if_called(self)
            bar = fails_if_called(self)
        _cfg_ctx = _makeConfigContext()
        self._callFUT(_cfg_ctx, [_View], IViewType, '', for_=(Interface,),
                      permission='testing', allowed_interface=(IViewType,))
        self.assertEqual(_cfg_ctx._actions[0][0], ())
        # Register the adapter
        action =_cfg_ctx._actions[0][1]
        self.assertEqual(action['callable'], handler)
        self.assertEqual(action['discriminator'],
                         ('view', (Interface, IViewType), '', Interface))
        self.assertEqual(action['args'][0], 'registerAdapter')
        factory = action['args'][1]
        checker = factory.checker
        self.assertEqual(checker.get_permissions, {'bar': 'testing'})


class Test_resource(unittest.TestCase):

    def _callFUT(self, *args, **kw):
        from zope.component.zcml import resource
        return resource(*args, **kw)

    def test_w_allowed_interface_wo_permission(self):
        from zope.interface import Interface
        from zope.component.zcml import ComponentConfigurationError
        class IResourceType(Interface):
            pass
        class IView(Interface):
            def foo():
                "foo"
            def bar():
                "bar"
        class _Resource(object):
            __init__ = fails_if_called(self)
            foo = fails_if_called(self)
            bar = fails_if_called(self)
        _cfg_ctx = _makeConfigContext()
        self.assertRaises(ComponentConfigurationError,
                          self._callFUT,
                            _cfg_ctx, (_Resource,), IResourceType, '',
                            allowed_interface=IView)

    def test_w_allowed_attributes_wo_permission(self):
        from zope.interface import Interface
        from zope.component.zcml import ComponentConfigurationError
        class IResourceType(Interface):
            pass
        class _Resource(object):
            __init__ = fails_if_called(self)
            foo = fails_if_called(self)
            bar = fails_if_called(self)
        _cfg_ctx = _makeConfigContext()
        self.assertRaises(ComponentConfigurationError,
                          self._callFUT,
                            _cfg_ctx, (_Resource,), IResourceType, '',
                            allowed_attributes=('foo', 'bar'))

    def test_wo_permission_w_name(self):
        from zope.interface import Interface
        from zope.component.interface import provideInterface
        from zope.component.zcml import handler
        class IResourceType(Interface):
            pass
        class _Resource(object):
            __init__ = fails_if_called(self)
            foo = fails_if_called(self)
            bar = fails_if_called(self)
        _cfg_ctx = _makeConfigContext()
        self._callFUT(_cfg_ctx, _Resource, IResourceType, 'test')
        self.assertEqual(len(_cfg_ctx._actions), 3)
        self.assertEqual(_cfg_ctx._actions[0][0], ())
        # Register the resource
        action =_cfg_ctx._actions[0][1]
        self.assertEqual(action['callable'], handler)
        self.assertEqual(action['discriminator'],
                         ('resource', 'test', IResourceType, Interface))
        self.assertEqual(action['args'][0], 'registerAdapter')
        self.assertEqual(action['args'][1], _Resource)
        self.assertEqual(action['args'][2], (IResourceType,))
        self.assertEqual(action['args'][3], Interface)
        self.assertEqual(action['args'][4], 'test')
        self.assertEqual(action['args'][5], 'TESTING')
        # Register the 'type' interface
        self.assertEqual(_cfg_ctx._actions[1][0], ())
        action =_cfg_ctx._actions[1][1]
        self.assertEqual(action['callable'], provideInterface)
        self.assertEqual(action['discriminator'], None)
        self.assertEqual(action['args'], ('', IResourceType))
        # Register the required interface(s)
        self.assertEqual(_cfg_ctx._actions[2][0], ())
        action =_cfg_ctx._actions[2][1]
        self.assertEqual(action['callable'], provideInterface)
        self.assertEqual(action['discriminator'], None)
        self.assertEqual(action['args'], ('', Interface))

    @skipIfNoSecurity
    def test_w_permission(self):
        from zope.interface import Interface
        from zope.component.zcml import handler
        class IResourceType(Interface):
            pass
        class _Resource(object):
            def __init__(self, context):
                self.context = context
            foo = fails_if_called(self)
            bar = fails_if_called(self)
        _cfg_ctx = _makeConfigContext()
        self._callFUT(_cfg_ctx, _Resource, IResourceType, 'test',
                      permission='testing', allowed_attributes=('foo',))
        self.assertEqual(len(_cfg_ctx._actions), 3)
        self.assertEqual(_cfg_ctx._actions[0][0], ())
        # Register the resource
        action =_cfg_ctx._actions[0][1]
        self.assertEqual(action['callable'], handler)
        self.assertEqual(action['discriminator'],
                         ('resource', 'test', IResourceType, Interface))
        self.assertEqual(action['args'][0], 'registerAdapter')
        factory = action['args'][1]
        self.assertTrue(factory.factory is _Resource)
        context = object()
        resource = factory(context)
        checker = resource.__Security_checker__
        self.assertEqual(checker.get_permissions, {'foo': 'testing'})
        self.assertTrue(resource.context is context)
        self.assertEqual(action['args'][2], (IResourceType,))
        self.assertEqual(action['args'][3], Interface)
        self.assertEqual(action['args'][4], 'test')
        self.assertEqual(action['args'][5], 'TESTING')


def _makeConfigContext():
    class _Context(object):
        info = 'TESTING'
        def __init__(self):
            self._actions = []
        def action(self, *args, **kw):
            self._actions.append((args, kw))
    return _Context()
