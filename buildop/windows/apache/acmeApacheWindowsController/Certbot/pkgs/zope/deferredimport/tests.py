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
import unittest


class DeferredTests(unittest.TestCase):

    def _getTargetClass(self):
        from zope.deferredimport.deferredmodule import Deferred
        return Deferred

    def _makeOne(self, *args, **kw):
        return self._getTargetClass()(*args, **kw)

    def test_ctor(self):
        name = 'TESTING'
        specifier = 'foo:bar'
        deferred = self._makeOne(name, specifier)
        self.assertEqual(deferred.__name__, name)
        self.assertEqual(deferred.specifier, specifier)

    def test_get_just_module(self):
        name = 'TESTING'
        specifier = 'zope.deferredimport.deferredmodule'
        deferred = self._makeOne(name, specifier)
        from zope.deferredimport import deferredmodule
        self.assertTrue(deferred.get() is deferredmodule)

    def test_get_module_and_name(self):
        name = 'TESTING'
        specifier = 'zope.deferredimport.deferredmodule:Deferred'
        deferred = self._makeOne(name, specifier)
        self.assertTrue(deferred.get() is self._getTargetClass())


class TestModuleProxy(unittest.TestCase):

    def test_getattr_with_no_deferred(self):
        from zope.deferredimport.deferredmodule import ModuleProxy
        proxy = ModuleProxy(self)
        with self.assertRaises(AttributeError):
            getattr(proxy, 'no_name')

    def test_preserves_docstring(self):
        from zope.deferredimport import deferredmodule

        proxy = deferredmodule.ModuleProxy(deferredmodule)
        self.assertEqual(deferredmodule.__doc__, proxy.__doc__)

    def test_preserves_name(self):
        from zope.deferredimport import deferredmodule

        proxy = deferredmodule.ModuleProxy(deferredmodule)
        self.assertEqual(deferredmodule.__name__, proxy.__name__)


def test_suite():
    return unittest.defaultTestLoader.loadTestsFromName(__name__)
