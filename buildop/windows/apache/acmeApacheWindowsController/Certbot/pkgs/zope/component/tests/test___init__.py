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

import unittest

class Test_package(unittest.TestCase):

    def test_module_conforms_to_IComponentArchitecture(self):
        from zope.interface.verify import verifyObject
        from zope.component.interfaces import IComponentArchitecture
        import zope.component as zc
        verifyObject(IComponentArchitecture, zc)

    def test_module_conforms_to_IComponentRegistrationConvenience(self):
        from zope.interface.verify import verifyObject
        from zope.component.interfaces import IComponentRegistrationConvenience
        import zope.component as zc
        verifyObject(IComponentRegistrationConvenience, zc)


class Test_Interface_call(unittest.TestCase):

    from zope.component.testing import setUp, tearDown

    def test_miss(self):
        from zope.interface import Interface
        class IFoo(Interface):
            pass
        self.assertRaises(TypeError, IFoo, object())

    def test_miss_w_default(self):
        from zope.interface import Interface
        class IFoo(Interface):
            pass
        marker = object()
        self.assertTrue(IFoo(object(), marker) is marker)

    def test_hit(self):
        from zope.interface import Interface
        from zope.interface import implementer
        from zope.component import getGlobalSiteManager
        class IFoo(Interface):
            pass
        class IBar(Interface):
            pass
        @implementer(IBar)
        class Bar(object):
            pass
        @implementer(IFoo)
        class Baz(object):
            def __init__(self, context):
                self.context = context
        getGlobalSiteManager().registerAdapter(Baz, (IBar,), IFoo, '')
        bar = Bar()
        adapted = IFoo(bar)
        self.assertTrue(adapted.__class__ is Baz)
        self.assertTrue(adapted.context is bar)

    def test_hit_registered_for_None(self):
        from zope.interface import Interface
        from zope.interface import implementer
        from zope.component import getGlobalSiteManager
        class IFoo(Interface):
            pass
        @implementer(IFoo)
        class Baz(object):
            def __init__(self, context):
                self.context = context
        getGlobalSiteManager().registerAdapter(Baz, (None,), IFoo, '')
        ctx = object()
        adapted = IFoo(ctx)
        self.assertTrue(adapted.__class__ is Baz)
        self.assertTrue(adapted.context is ctx)



def test_suite():
    return unittest.TestSuite((
        unittest.makeSuite(Test_package),
        unittest.makeSuite(Test_Interface_call),
    ))
