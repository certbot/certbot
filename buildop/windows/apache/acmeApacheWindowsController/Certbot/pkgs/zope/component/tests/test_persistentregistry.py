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


def skipIfNoPersistent(testfunc):
    try:
        import persistent
    except ImportError: # pragma: no cover
        return unittest.skip("persistent not installed")(testfunc)
    return testfunc

@skipIfNoPersistent
class PersistentAdapterRegistryTests(unittest.TestCase):

    def _getTargetClass(self):
        from zope.component.persistentregistry import PersistentAdapterRegistry
        return PersistentAdapterRegistry

    def _makeOne(self, *args, **kw):
        return self._getTargetClass()(*args, **kw)

    def _makeCache(self, jar):
        # Borrowed from persistent.tests.test_pyPersistence.

        class _Cache(object):
            def __init__(self, jar):
                self._jar = jar
                self._mru = []
                # mru(oid) is only called in pure-Python runs
                self.mru = self._mru.append
            def new_ghost(self, oid, obj):
                obj._p_jar = self._jar
                obj._p_oid = oid
            def update_object_size_estimation(self, oid, size):
                "This is only called in pure-Python runs"

        return _Cache(jar)

    def _makeJar(self):
        # Borrowed from persistent.tests.test_pyPersistence.
        from zope.interface import implementer
        from persistent.interfaces import IPersistentDataManager

        @implementer(IPersistentDataManager)
        class _Jar(object):
            def __init__(self):
                self._loaded = []
                self._registered = []
            def setstate(self, obj):
                self._loaded.append(obj._p_oid)
            def register(self, obj):
                self._registered.append(obj._p_oid)

        jar = _Jar()
        jar._cache = self._makeCache(jar)
        return jar

    def _makeOneWithJar(self, dirty=False, **kw):
        # Borrowed from persistent.tests.test_pyPersistence.
        OID = _makeOctets('\x01' * 8)
        inst = self._makeOne(**kw)
        jar = self._makeJar()
        jar._cache.new_ghost(OID, inst) # assigns _p_jar, _p_oid
        return inst, jar, OID

    def test_changed_original_is_not_us(self):
        registry, jar, OID = self._makeOneWithJar()
        self.assertEqual(registry._generation, 1)
        registry.changed(object())
        # 'originally_changed' is not us, but we are still dirty because
        # '_generation' gets bumped.
        self.assertEqual(registry._p_changed, True)
        # base class gets called
        self.assertEqual(registry._generation, 2)

    def test_changed_original_is_us(self):
        registry, jar, OID = self._makeOneWithJar()
        self.assertEqual(registry._generation, 1)
        registry.changed(registry)
        # 'originally_changed' is not us, so not dirty
        self.assertEqual(registry._p_changed, True)
        # base class gets called
        self.assertEqual(registry._generation, 2)

    def test___getstate___simple(self):
        from zope.component import globalSiteManager
        bases = (globalSiteManager.adapters, globalSiteManager.utilities)
        registry, jar, OID = self._makeOneWithJar(bases=bases)
        state = registry.__getstate__()
        self.assertEqual(state['__bases__'], bases)
        self.assertEqual(state['_generation'], 1)
        self.assertEqual(state['_provided'], {})
        self.assertEqual(state['_adapters'], [])
        self.assertEqual(state['_subscribers'], [])
        self.assertFalse('ro' in state)

    def test___getstate___skips_delegated_names(self):
        registry, jar, OID = self._makeOneWithJar()
        registry.names = lambda *args: ['a', 'b', 'c']
        self.assertFalse('names' in registry.__getstate__())

    def test___setstate___rebuilds__v_lookup(self):
        registry, jar, OID = self._makeOneWithJar()
        state = registry.__getstate__()
        self.assertTrue('_v_lookup' in registry.__dict__)
        registry._p_changed = None # clears volatile '_v_lookup'
        self.assertFalse('_v_lookup' in registry.__dict__)
        registry.__setstate__(state)
        self.assertTrue('_v_lookup' in registry.__dict__)

    def test___setstate___rebuilds__ro(self):
        from zope.component import globalSiteManager
        bases = (globalSiteManager.adapters, globalSiteManager.utilities)
        registry, jar, OID = self._makeOneWithJar(bases=bases)
        state = registry.__getstate__()
        registry.__setstate__(state)
        self.assertEqual(registry.__bases__, bases)
        self.assertEqual(registry.ro, [registry] + list(bases))

@skipIfNoPersistent
class PersistentComponentsTests(unittest.TestCase):

    def _getTargetClass(self):
        from zope.component.persistentregistry import PersistentComponents
        return PersistentComponents

    def _makeOne(self, *args, **kw):
        return self._getTargetClass()(*args, **kw)

    def test_ctor_initializes_registries_and_registrations(self):
        from persistent.mapping import PersistentMapping
        from persistent.list import PersistentList
        from zope.component.persistentregistry import PersistentAdapterRegistry
        registry = self._makeOne()
        self.assertTrue(isinstance(registry.adapters,
                                   PersistentAdapterRegistry))
        self.assertTrue(isinstance(registry.utilities,
                                   PersistentAdapterRegistry))
        self.assertTrue(isinstance(registry._adapter_registrations,
                                   PersistentMapping))
        self.assertTrue(isinstance(registry._utility_registrations,
                                   PersistentMapping))
        self.assertTrue(isinstance(registry._subscription_registrations,
                                   PersistentList))
        self.assertTrue(isinstance(registry._handler_registrations,
                                   PersistentList))

def _makeOctets(s):
    return bytes(s) if bytes is str else bytes(s, 'ascii')
