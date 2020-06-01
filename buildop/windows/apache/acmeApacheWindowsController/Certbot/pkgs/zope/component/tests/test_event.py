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
"""Test adapter declaration helpers
"""
import unittest

class Test_dispatch(unittest.TestCase):

    def test_it(self):
        from zope.interface import Interface
        from zope.component.globalregistry import getGlobalSiteManager
        from zope.component.event import dispatch
        _adapted = []
        def _adapter(context):
            _adapted.append(context)
            return object()
        gsm = getGlobalSiteManager()
        gsm.registerHandler(_adapter, (Interface,))
        del _adapted[:] # clear handler reg
        event = object()
        dispatch(event)
        self.assertEqual(_adapted, [event])

class Test_objectEventNotify(unittest.TestCase):

    def test_it(self):
        from zope.interface import Interface
        from zope.interface import implementer
        from zope.component.globalregistry import getGlobalSiteManager
        from zope.interface.interfaces import IObjectEvent
        from zope.component.event import objectEventNotify
        _adapted = []
        def _adapter(context, event):
            _adapted.append((context, event))
            return object()
        gsm = getGlobalSiteManager()
        gsm.registerHandler(_adapter, (Interface, IObjectEvent))
        del _adapted[:] # clear handler reg
        @implementer(IObjectEvent)
        class _ObjectEvent(object):
            def __init__(self, object):
                self.object = object
        context = object()
        event = _ObjectEvent(context)
        objectEventNotify(event)
        self.assertEqual(_adapted, [(context, event)])



def test_suite():
    return unittest.TestSuite((
        unittest.makeSuite(Test_dispatch),
        unittest.makeSuite(Test_objectEventNotify),
    ))
