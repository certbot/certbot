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
"""Tests for z.c.registry
"""
import unittest

from zope.component.tests import fails_if_called

class Test_dispatchUtilityRegistrationEvent(unittest.TestCase):

    from zope.component.testing import setUp, tearDown

    def _callFUT(self, *args, **kw):
        from zope.component.registry import dispatchUtilityRegistrationEvent
        return dispatchUtilityRegistrationEvent(*args, **kw)

    def test_it(self):
        from zope.component import registry
        class _Registration(object):
            component = object()
        _EVENT = object()
        _handled = []
        def _handle(*args):
            _handled.append(args)
        with _Monkey(registry, handle=_handle):
            self._callFUT(_Registration(), _EVENT)
        self.assertEqual(_handled, [(_Registration.component, _EVENT)])


class Test_dispatchAdapterRegistrationEvent(unittest.TestCase):

    from zope.component.testing import setUp, tearDown

    def _callFUT(self, *args, **kw):
        from zope.component.registry import dispatchAdapterRegistrationEvent
        return dispatchAdapterRegistrationEvent(*args, **kw)

    def test_it(self):
        from zope.component import registry
        class _Registration(object):
            factory = fails_if_called(self)
        _registration = _Registration()
        _EVENT = object()
        _handled = []
        def _handle(*args):
            _handled.append(args)
        with _Monkey(registry, handle=_handle):
            self._callFUT(_registration, _EVENT)
        self.assertEqual(_handled, [(_registration.factory, _EVENT)])


class Test_dispatchSubscriptionAdapterRegistrationEvent(unittest.TestCase):

    from zope.component.testing import setUp, tearDown

    def _callFUT(self, *args, **kw):
        from zope.component.registry \
            import dispatchSubscriptionAdapterRegistrationEvent
        return dispatchSubscriptionAdapterRegistrationEvent(*args, **kw)

    def test_it(self):
        from zope.component import registry
        class _Registration(object):
            factory = fails_if_called(self)
        _registration = _Registration()
        _EVENT = object()
        _handled = []
        def _handle(*args):
            _handled.append(args)
        with _Monkey(registry, handle=_handle):
            self._callFUT(_registration, _EVENT)
        self.assertEqual(_handled, [(_registration.factory, _EVENT)])


class Test_dispatchHandlerRegistrationEvent(unittest.TestCase):

    from zope.component.testing import setUp, tearDown

    def _callFUT(self, *args, **kw):
        from zope.component.registry import dispatchHandlerRegistrationEvent
        return dispatchHandlerRegistrationEvent(*args, **kw)

    def test_it(self):
        from zope.component import registry
        class _Registration(object):
            handler = fails_if_called(self)
        _registration = _Registration()
        _EVENT = object()
        _handled = []
        def _handle(*args):
            _handled.append(args)
        with _Monkey(registry, handle=_handle):
            self._callFUT(_registration, _EVENT)
        self.assertEqual(_handled, [(_registration.handler, _EVENT)])


class TestBackwardsCompat(unittest.TestCase):

    def test_interface_warnings(self):
        from zope.component import registry
        import warnings
        for name in (
                'Components',
                '_getUtilityProvided',
                '_getAdapterProvided',
                '_getAdapterRequired',
                'UtilityRegistration',
                'AdapterRegistration',
                'SubscriptionRegistration',
                'HandlerRegistration',
        ):
            with warnings.catch_warnings(record=True) as log:
                warnings.simplefilter("always")
                getattr(registry, name)

                self.assertEqual(1, len(log), name)
                message = str(log[0].message)
                self.assertIn(name, message)
                self.assertIn("Import from zope.interface.registry", message)


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
