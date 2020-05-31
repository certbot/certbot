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
"""Tests for z.c.interface
"""
import unittest


class Test_provideInterface(unittest.TestCase):

    from zope.component.testing import setUp, tearDown

    def _callFUT(self, *args, **kw):
        from zope.component.interface import provideInterface
        return provideInterface(*args, **kw)

    def test_w_interface_not_IInterface(self):
        self.assertRaises(TypeError, self._callFUT, 'xxx', object())

    def test_w_iface_type_not_IInterface(self):
        from zope.interface import Interface
        from zope.interface.interface import InterfaceClass
        class IFoo(Interface):
            pass
        IBar = InterfaceClass('IBar')
        self.assertRaises(TypeError, self._callFUT, 'xxx', IFoo, IBar)

    def test_w_class(self):
        from zope.interface.interfaces import IInterface
        from zope.component.globalregistry import getGlobalSiteManager
        gsm = getGlobalSiteManager()
        class IBar(IInterface):
            pass
        class Foo(object):
            pass
        self._callFUT('', Foo, IBar)
        self.assertFalse(IBar.providedBy(Foo))
        self.assertEqual(len(list(gsm.getUtilitiesFor(IBar))), 0)

    def test_wo_name_w_iface_type(self):
        from zope.interface import Interface
        from zope.interface.interfaces import IInterface
        from zope.component.globalregistry import getGlobalSiteManager
        gsm = getGlobalSiteManager()
        class IFoo(Interface):
            pass
        class IBar(IInterface):
            pass
        self._callFUT('', IFoo, IBar)
        self.assertTrue(IBar.providedBy(IFoo))
        nm = 'zope.component.tests.test_interface.IFoo'
        self.assertTrue(gsm.getUtility(IBar, nm) is IFoo)

    def test_w_name_wo_ifact_type(self):
        from zope.interface import Interface
        from zope.interface.interfaces import IInterface
        from zope.component.globalregistry import getGlobalSiteManager
        gsm = getGlobalSiteManager()
        class IFoo(Interface):
            pass
        self._callFUT('foo', IFoo)
        self.assertTrue(IInterface.providedBy(IFoo))
        registered = gsm.getUtility(IInterface, name='foo')
        self.assertTrue(registered is IFoo)


class Test_getInterface(unittest.TestCase):

    from zope.component.testing import setUp, tearDown

    def _callFUT(self, *args, **kw):
        from zope.component.interface import getInterface
        return getInterface(*args, **kw)

    def test_miss(self):
        from zope.interface.interfaces import ComponentLookupError
        self.assertRaises(ComponentLookupError,
                          self._callFUT, object(), 'nonesuch')

    def test_hit(self):
        from zope.interface import Interface
        from zope.interface.interfaces import IInterface
        from zope.component.globalregistry import getGlobalSiteManager
        gsm = getGlobalSiteManager()
        class IFoo(Interface):
            pass
        gsm.registerUtility(IFoo, IInterface, 'foo')
        self.assertTrue(self._callFUT(object(), 'foo') is IFoo)


class Test_queryInterface(unittest.TestCase):

    from zope.component.testing import setUp, tearDown

    def _callFUT(self, *args, **kw):
        from zope.component.interface import queryInterface
        return queryInterface(*args, **kw)

    def test_miss(self):
        _DEFAULT = object()
        self.assertTrue(
            self._callFUT('nonesuch', default=_DEFAULT) is _DEFAULT)

    def test_hit(self):
        from zope.interface import Interface
        from zope.interface.interfaces import IInterface
        from zope.component.globalregistry import getGlobalSiteManager
        gsm = getGlobalSiteManager()
        class IFoo(Interface):
            pass
        gsm.registerUtility(IFoo, IInterface, 'foo')
        self.assertTrue(self._callFUT('foo') is IFoo)


class Test_searchInterface(unittest.TestCase):

    from zope.component.testing import setUp, tearDown

    def _callFUT(self, *args, **kw):
        from zope.component.interface import searchInterface
        return searchInterface(*args, **kw)

    def test_empty(self):
        self.assertEqual(self._callFUT(object()), [])

    def test_no_search_string_no_base(self):
        from zope.interface import Interface
        from zope.interface.interfaces import IInterface
        from zope.component.globalregistry import getGlobalSiteManager
        gsm = getGlobalSiteManager()
        class IFoo(Interface):
            pass
        gsm.registerUtility(IFoo, IInterface, 'foo')
        self.assertEqual(self._callFUT(object()), [IFoo])

    def test_w_search_string_no_base(self):
        from zope.interface import Interface
        from zope.interface.interfaces import IInterface
        from zope.component.globalregistry import getGlobalSiteManager
        gsm = getGlobalSiteManager()
        class IFoo(Interface):
            pass
        class IBar(Interface):
            pass
        gsm.registerUtility(IFoo, IInterface, 'foo')
        gsm.registerUtility(IBar, IInterface, 'bar')
        self.assertEqual(self._callFUT(object(), 'IFoo'), [IFoo])

    def test_no_search_string_w_base(self):
        from zope.interface import Interface
        from zope.interface.interfaces import IInterface
        from zope.component.globalregistry import getGlobalSiteManager
        gsm = getGlobalSiteManager()
        class IBase(Interface):
            pass
        class IFoo(IBase):
            pass
        class IBar(Interface):
            pass
        gsm.registerUtility(IFoo, IInterface, 'foo')
        gsm.registerUtility(IBar, IInterface, 'bar')
        self.assertEqual(self._callFUT(object(), base=IBase), [IFoo])


class Test_searchInterfaceIds(unittest.TestCase):

    from zope.component.testing import setUp, tearDown

    def _callFUT(self, *args, **kw):
        from zope.component.interface import searchInterfaceIds
        return searchInterfaceIds(*args, **kw)

    def test_empty(self):
        self.assertEqual(self._callFUT(object()), [])

    def test_no_search_string_no_base(self):
        from zope.interface import Interface
        from zope.interface.interfaces import IInterface
        from zope.component.globalregistry import getGlobalSiteManager
        gsm = getGlobalSiteManager()
        class IFoo(Interface):
            pass
        gsm.registerUtility(IFoo, IInterface, 'foo')
        self.assertEqual(self._callFUT(object()), ['foo'])

    def test_w_search_string_no_base(self):
        from zope.interface import Interface
        from zope.interface.interfaces import IInterface
        from zope.component.globalregistry import getGlobalSiteManager
        gsm = getGlobalSiteManager()
        class IFoo(Interface):
            pass
        class IBar(Interface):
            pass
        gsm.registerUtility(IFoo, IInterface, 'foo')
        gsm.registerUtility(IBar, IInterface, 'bar')
        self.assertEqual(self._callFUT(object(), 'IFoo'), ['foo'])

    def test_no_search_string_w_base(self):
        from zope.interface import Interface
        from zope.interface.interfaces import IInterface
        from zope.component.globalregistry import getGlobalSiteManager
        gsm = getGlobalSiteManager()
        class IBase(Interface):
            pass
        class IFoo(IBase):
            pass
        class IBar(Interface):
            pass
        gsm.registerUtility(IFoo, IInterface, 'foo')
        gsm.registerUtility(IBar, IInterface, 'bar')
        self.assertEqual(self._callFUT(object(), base=IBase), ['foo'])


class Test_searchInterfaceUtilities(unittest.TestCase):

    from zope.component.testing import setUp, tearDown

    def _callFUT(self, *args, **kw):
        from zope.component.interface import searchInterfaceUtilities
        return searchInterfaceUtilities(*args, **kw)

    def test_empty(self):
        self.assertEqual(self._callFUT(object()), [])

    def test_no_search_string_no_base(self):
        from zope.interface import Interface
        from zope.interface.interfaces import IInterface
        from zope.component.globalregistry import getGlobalSiteManager
        gsm = getGlobalSiteManager()
        class IFoo(Interface):
            pass
        gsm.registerUtility(IFoo, IInterface, 'foo')
        self.assertEqual(self._callFUT(object()), [('foo', IFoo)])

    def test_w_search_string_no_base(self):
        from zope.interface import Interface
        from zope.interface.interfaces import IInterface
        from zope.component.globalregistry import getGlobalSiteManager
        gsm = getGlobalSiteManager()
        class IFoo(Interface):
            pass
        class IBar(Interface):
            pass
        gsm.registerUtility(IFoo, IInterface, 'foo')
        gsm.registerUtility(IBar, IInterface, 'bar')
        self.assertEqual(self._callFUT(object(), 'IFoo'), [('foo', IFoo)])

    def test_no_search_string_w_base(self):
        from zope.interface import Interface
        from zope.interface.interfaces import IInterface
        from zope.component.globalregistry import getGlobalSiteManager
        gsm = getGlobalSiteManager()
        class IBase(Interface):
            pass
        class IFoo(IBase):
            pass
        class IBar(Interface):
            pass
        gsm.registerUtility(IFoo, IInterface, 'foo')
        gsm.registerUtility(IBar, IInterface, 'bar')
        self.assertEqual(self._callFUT(object(), base=IBase), [('foo', IFoo)])

    def test_no_search_string_w_base_is_same(self):
        from zope.interface import Interface
        from zope.interface.interfaces import IInterface
        from zope.component.globalregistry import getGlobalSiteManager
        gsm = getGlobalSiteManager()
        class IFoo(Interface):
            pass
        class IBar(Interface):
            pass
        gsm.registerUtility(IFoo, IInterface, 'foo')
        gsm.registerUtility(IBar, IInterface, 'bar')
        self.assertEqual(self._callFUT(object(), base=IFoo), [('foo', IFoo)])


class Test_getInterfaceAllDocs(unittest.TestCase):

    def _callFUT(self, *args, **kw):
        from zope.component.interface import getInterfaceAllDocs
        return getInterfaceAllDocs(*args, **kw)

    def test_w_class(self):
        class Foo(object):
            """DOCSTRING"""
            bar = None
            def baz(self):
                """BAZ"""
        self.assertEqual(self._callFUT(Foo),
                         'zope.component.tests.test_interface.foo\n' +
                         'docstring')

    def test_w_interface_no_members(self):
        from zope.interface import Interface
        class IFoo(Interface):
            """DOCSTRING"""
        self.assertEqual(self._callFUT(IFoo),
                         'zope.component.tests.test_interface.ifoo\n' +
                         'docstring')

    def test_w_interface_w_members(self):
        from zope.interface import Attribute
        from zope.interface import Interface
        class IFoo(Interface):
            """DOCSTRING"""
            bar = Attribute('bar', 'Do bar')
            def baz(self):
                """BAZ"""
        self.assertEqual(self._callFUT(IFoo),
                         'zope.component.tests.test_interface.ifoo\n' +
                         'docstring\n' +
                         'do bar\n' +
                         'baz')


class Test_nameToInterface(unittest.TestCase):

    from zope.component.testing import setUp, tearDown

    def _callFUT(self, *args, **kw):
        from zope.component.interface import nameToInterface
        return nameToInterface(*args, **kw)

    def test_w_None(self):
        self.assertTrue(self._callFUT(object(), 'None') is None)

    def test_miss(self):
        from zope.interface.interfaces import ComponentLookupError
        self.assertRaises(ComponentLookupError,
                          self._callFUT, object(), 'nonesuch')

    def test_hit(self):
        from zope.interface import Interface
        from zope.interface.interfaces import IInterface
        from zope.component.globalregistry import getGlobalSiteManager
        gsm = getGlobalSiteManager()
        class IFoo(Interface):
            pass
        gsm.registerUtility(IFoo, IInterface, 'foo')
        found = self._callFUT(object(), 'foo')
        self.assertTrue(found is IFoo)


class Test_interfaceToName(unittest.TestCase):

    from zope.component.testing import setUp, tearDown

    def _callFUT(self, *args, **kw):
        from zope.component.interface import interfaceToName
        return interfaceToName(*args, **kw)

    def test_w_None(self):
        self.assertEqual(self._callFUT(object(), None), 'None')

    def test_w_unregistered(self):
        from zope.interface import Interface
        class IFoo(Interface):
            pass
        self.assertEqual(self._callFUT(object(), IFoo),
                         'zope.component.tests.test_interface.IFoo')

    def test_w_registered(self):
        from zope.interface import Interface
        from zope.interface.interfaces import IInterface
        from zope.component.globalregistry import getGlobalSiteManager
        gsm = getGlobalSiteManager()
        class IFoo(Interface):
            pass
        gsm.registerUtility(IFoo, IInterface, 'foo')
        self.assertEqual(self._callFUT(object(), IFoo),
                         'zope.component.tests.test_interface.IFoo')


def test_suite():
    return unittest.TestSuite((
        unittest.makeSuite(Test_provideInterface),
        unittest.makeSuite(Test_getInterface),
        unittest.makeSuite(Test_queryInterface),
        unittest.makeSuite(Test_searchInterface),
        unittest.makeSuite(Test_searchInterfaceIds),
        unittest.makeSuite(Test_searchInterfaceUtilities),
        unittest.makeSuite(Test_getInterfaceAllDocs),
        unittest.makeSuite(Test_nameToInterface),
        unittest.makeSuite(Test_interfaceToName),
    ))
