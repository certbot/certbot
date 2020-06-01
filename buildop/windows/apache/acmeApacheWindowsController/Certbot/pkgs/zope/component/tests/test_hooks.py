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
"""Tests for z.c.hooks
"""
import unittest


class Test_read_property(unittest.TestCase):

    def _getTargetClass(self):
        from zope.component.hooks import read_property
        return read_property

    def test_via_instance(self):
        class Foo(object):
            @self._getTargetClass()
            def bar(self):
                return 'BAR'
        foo = Foo()
        self.assertEqual(foo.bar, 'BAR')
        foo.bar = 'BAZ'
        self.assertEqual(foo.bar, 'BAZ')
        del foo.bar
        self.assertEqual(foo.bar, 'BAR')

    def test_via_class(self):
        class Foo(object):
            @self._getTargetClass()
            def bar(self):
                return 'BAR'
        bar = Foo.bar
        self.assertTrue(isinstance(bar, self._getTargetClass()))
        self.assertEqual(bar.func(object()), 'BAR')


class SiteInfoTests(unittest.TestCase):

    def _getTargetClass(self):
        from zope.component.hooks import SiteInfo
        return SiteInfo

    def _makeOne(self):
        return self._getTargetClass()()

    def test_initial(self):
        from zope.component.globalregistry import getGlobalSiteManager
        gsm = getGlobalSiteManager()
        si = self._makeOne()
        self.assertEqual(si.site, None)
        self.assertTrue(si.sm is gsm)

    def test_adapter_hook(self):
        _hook = object()
        class _Registry(object):
            adapter_hook = _hook
        class _SiteManager(object):
            adapters = _Registry()
        si = self._makeOne()
        si.sm = _SiteManager()
        self.assertFalse('adapter_hook' in si.__dict__)
        self.assertTrue(si.adapter_hook is _hook)
        self.assertTrue('adapter_hook' in si.__dict__)
        del si.adapter_hook
        self.assertFalse('adapter_hook' in si.__dict__)


class Test_setSite(unittest.TestCase):

    def _callFUT(self, site):
        from zope.component.hooks import setSite
        return setSite(site)

    def test_w_None(self):
        from zope.component import hooks
        from zope.component.globalregistry import getGlobalSiteManager
        gsm = getGlobalSiteManager()
        _SM2 = object()
        _SITE = object()
        _HOOK = object()
        siteinfo = _DummySiteInfo()
        siteinfo.sm = _SM2
        siteinfo.site = _SITE
        siteinfo.adapterhook = _HOOK
        with _Monkey(hooks, siteinfo=siteinfo):
            self._callFUT(None)
        self.assertTrue(siteinfo.sm is gsm)
        self.assertTrue(siteinfo.site is None)
        self.assertFalse('adapter_hook' in siteinfo.__dict__)

    def test_w_site(self):
        from zope.component import hooks
        _SM2 = object()
        class _Site(object):
            def getSiteManager(self):
                return _SM2
        siteinfo = _DummySiteInfo()
        _site = _Site()
        with _Monkey(hooks, siteinfo=siteinfo):
            self._callFUT(_site)
        self.assertTrue(siteinfo.sm is _SM2)
        self.assertTrue(siteinfo.site is _site)
        self.assertFalse('adapter_hook' in siteinfo.__dict__)


class Test_getSite(unittest.TestCase):

    def _callFUT(self):
        from zope.component.hooks import getSite
        return getSite()

    def test_w_None(self):
        from zope.component import hooks
        from zope.component.globalregistry import getGlobalSiteManager
        gsm = getGlobalSiteManager()
        siteinfo = _DummySiteInfo()
        with _Monkey(hooks, siteinfo=siteinfo):
            self.assertTrue(self._callFUT() is None)

    def test_w_site(self):
        from zope.component import hooks
        from zope.component.globalregistry import getGlobalSiteManager
        gsm = getGlobalSiteManager()
        _SM2 = object()
        _SITE = object()
        siteinfo = _DummySiteInfo()
        siteinfo.sm = _SM2
        siteinfo.site = _SITE
        with _Monkey(hooks, siteinfo=siteinfo):
            self.assertTrue(self._callFUT() is _SITE)


class Test_site(unittest.TestCase):

    def _callFUT(self, new_site):
        from zope.component.hooks import site
        return site(new_site)

    def test_it(self):
        from zope.component import hooks
        from zope.component.globalregistry import getGlobalSiteManager
        gsm = getGlobalSiteManager()
        _SM2 = object()
        class _Site(object):
            def getSiteManager(self):
                return _SM2
        _site = _Site()
        siteinfo = _DummySiteInfo()
        self.assertTrue(siteinfo.site is None)
        self.assertTrue(siteinfo.sm is _SM)
        with _Monkey(hooks, siteinfo=siteinfo):
            with self._callFUT(_site):
                self.assertTrue(siteinfo.site is _site)
                self.assertTrue(siteinfo.sm is _SM2)
            self.assertTrue(siteinfo.site is None)
            self.assertTrue(siteinfo.sm is gsm)


class Test_getSiteManager(unittest.TestCase):

    def _callFUT(self, context=None):
        from zope.component.hooks import getSiteManager
        return getSiteManager(context)

    def test_default(self):
        from zope.component import hooks
        from zope.component.globalregistry import getGlobalSiteManager
        gsm = getGlobalSiteManager()
        _SM2 = object()
        siteinfo = _DummySiteInfo()
        siteinfo.sm = _SM2
        with _Monkey(hooks, siteinfo=siteinfo):
            self.assertTrue(self._callFUT() is _SM2)

    def test_w_explicit_context_no_IComponentLookup(self):
        from zope.component import hooks
        from zope.component.globalregistry import getGlobalSiteManager
        gsm = getGlobalSiteManager()
        _SM2 = object()
        siteinfo = _DummySiteInfo()
        siteinfo.sm = _SM2
        with _Monkey(hooks, siteinfo=siteinfo):
            self.assertTrue(self._callFUT(object()) is gsm)

    def test_w_explicit_context_w_IComponentLookup(self):
        from zope.interface import Interface
        from zope.component import hooks
        from zope.component.globalregistry import getGlobalSiteManager
        from zope.interface.interfaces import IComponentLookup
        class _Lookup(object):
            def __init__(self, context):
                self.context = context
        gsm = getGlobalSiteManager()
        gsm.registerAdapter(_Lookup, (Interface,), IComponentLookup, '')
        _SM2 = object()
        siteinfo = _DummySiteInfo()
        siteinfo.sm = _SM2
        context = object()
        with _Monkey(hooks, siteinfo=siteinfo):
            sm = self._callFUT(context)
        self.assertTrue(isinstance(sm, _Lookup))
        self.assertTrue(sm.context is context)


class Test_adapter_hook(unittest.TestCase):

    def _callFUT(self, interface, object, name='', default=None):
        from zope.component.hooks import adapter_hook
        return adapter_hook(interface, object, name, default)

    def test_success(self):
        from zope.interface import Interface
        from zope.component import hooks
        from zope.component.globalregistry import getGlobalSiteManager
        class IFoo(Interface):
            pass
        gsm = getGlobalSiteManager()
        _ADAPTER = object()
        _DEFAULT = object()
        _CONTEXT = object()
        _called = []
        def _adapter_hook(interface, object, name, default):
            _called.append((interface, object, name, default))
            return _ADAPTER
        siteinfo = _DummySiteInfo()
        siteinfo.adapter_hook = _adapter_hook
        with _Monkey(hooks, siteinfo=siteinfo):
            adapter = self._callFUT(IFoo, _CONTEXT, 'bar', _DEFAULT)
        self.assertTrue(adapter is _ADAPTER)
        self.assertEqual(_called, [(IFoo, _CONTEXT, 'bar', _DEFAULT)])

    def test_hook_raises(self):
        from zope.interface import Interface
        from zope.component import hooks
        from zope.component.globalregistry import getGlobalSiteManager
        from zope.interface.interfaces import ComponentLookupError
        class IFoo(Interface):
            pass
        gsm = getGlobalSiteManager()
        _DEFAULT = object()
        _CONTEXT = object()
        _called = []
        def _adapter_hook(interface, object, name, default):
            _called.append((interface, object, name, default))
            raise ComponentLookupError('testing')
        siteinfo = _DummySiteInfo()
        siteinfo.adapter_hook = _adapter_hook
        with _Monkey(hooks, siteinfo=siteinfo):
            adapter = self._callFUT(IFoo, _CONTEXT, 'bar', _DEFAULT)
        self.assertTrue(adapter is _DEFAULT)
        self.assertEqual(_called, [(IFoo, _CONTEXT, 'bar', _DEFAULT)])


class Test_setHooks(unittest.TestCase):

    def _callFUT(self):
        from zope.component.hooks import setHooks
        return setHooks()

    def test_it(self):
        import zope.component._api
        from zope.component import hooks
        class _Hook(object):
            def __init__(self):
                self._hooked = None
            def sethook(self, value):
                self._hooked = value
        adapter_hook = _Hook()
        getSiteManager = _Hook()
        with _Monkey(zope.component._api,
                     adapter_hook=adapter_hook,
                     getSiteManager=getSiteManager):
            self._callFUT()
        self.assertEqual(adapter_hook._hooked, hooks.adapter_hook)
        self.assertEqual(getSiteManager._hooked, hooks.getSiteManager)


class Test_resetHooks(unittest.TestCase):

    def _callFUT(self):
        from zope.component.hooks import resetHooks
        return resetHooks()

    def test_it(self):
        import zope.component._api
        from zope.component import hooks
        class _Hook(object):
            def __init__(self):
                self._reset = False
            def reset(self):
                self._reset = True
        adapter_hook = _Hook()
        getSiteManager = _Hook()
        with _Monkey(zope.component._api,
                     adapter_hook=adapter_hook,
                     getSiteManager=getSiteManager):
            # Access the adapter_hook of the site info to be
            # sure it caches
            getattr(hooks.siteinfo, 'adapter_hook')
            self.assertTrue('adapter_hook' in hooks.siteinfo.__dict__)

            self._callFUT()

        self.assertTrue(adapter_hook._reset)
        self.assertTrue(getSiteManager._reset)
        # adapter_hook cache also reset
        self.assertFalse('adapter_hook' in hooks.siteinfo.__dict__)


_SM = object()
class _DummySiteInfo(object):
    sm = _SM
    site = None

class _Monkey(object):
    # context-manager for replacing module names in the scope of a test.
    def __init__(self, module, **kw):
        self.module = module
        self.to_restore = dict([(key, getattr(module, key)) for key in kw])
        for key, value in kw.items():
            setattr(module, key, value)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        for key, value in self.to_restore.items():
            setattr(self.module, key, value)


def test_suite():
    return unittest.TestSuite((
        unittest.makeSuite(Test_read_property),
        unittest.makeSuite(SiteInfoTests),
        unittest.makeSuite(Test_setSite),
        unittest.makeSuite(Test_getSite),
        unittest.makeSuite(Test_site),
        unittest.makeSuite(Test_getSiteManager),
        unittest.makeSuite(Test_adapter_hook),
        unittest.makeSuite(Test_setHooks),
        unittest.makeSuite(Test_resetHooks),
    ))
