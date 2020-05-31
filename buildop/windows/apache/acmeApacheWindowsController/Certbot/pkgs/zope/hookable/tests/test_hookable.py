##############################################################################
#
# Copyright (c) 2003 Zope Foundation and Contributors.
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
"""Test the hookable support Extension
"""
import unittest

def return_foo():
    return 'FOO'

def return_bar():
    return 'BAR'

def not_called():
    raise AssertionError("This should not be called")

class PyHookableMixin(object):

    def _callFUT(self, *args, **kw):
        from zope.hookable import _py_hookable
        return _py_hookable(*args, **kw)

class HookableMixin(object):

    def _callFUT(self, *args, **kw):
        from zope.hookable import hookable, _py_hookable
        if hookable is _py_hookable: # pragma: no cover
            raise unittest.SkipTest("Hookable and PyHookable are the same")
        return hookable(*args, **kw)


class PyHookableTests(PyHookableMixin,
                      unittest.TestCase):

    def test_pure_python(self):
        from zope.hookable import _PURE_PYTHON, hookable, _py_hookable, _c_hookable
        self.assertIs(hookable, _py_hookable if _PURE_PYTHON else _c_hookable)

    def test_before_hook(self):
        hooked = self._callFUT(return_foo)
        self.assertIs(hooked.original, return_foo)
        self.assertIs(hooked.implementation, return_foo)
        self.assertEqual(hooked(), 'FOO')

    def test_after_hook(self):
        hooked = self._callFUT(not_called)
        old = hooked.sethook(return_bar)
        self.assertIs(old, not_called)
        self.assertIs(hooked.original, not_called)
        self.assertIs(hooked.implementation, return_bar)
        self.assertEqual(hooked(), 'BAR')

    def test_after_hook_and_reset(self):
        hooked = self._callFUT(return_foo)
        old = hooked.sethook(not_called)
        hooked.reset()
        self.assertIs(old, return_foo)
        self.assertIs(hooked.original, return_foo)
        self.assertIs(hooked.implementation, return_foo)
        self.assertEqual(hooked(), 'FOO')

    def test_original_cannot_be_deleted(self):
        hooked = self._callFUT(not_called)
        with self.assertRaises((TypeError, AttributeError)):
            del hooked.original

    def test_implementation_cannot_be_deleted(self):
        hooked = self._callFUT(not_called)
        with self.assertRaises((TypeError, AttributeError)):
            del hooked.implementation

    def test_no_args(self):
        with self.assertRaises(TypeError):
            self._callFUT()

    def test_too_many_args(self):
        with self.assertRaises(TypeError):
            self._callFUT(not_called, not_called)

    def test_w_implementation_kwarg(self):
        hooked = self._callFUT(implementation=return_foo)
        self.assertIs(hooked.original, return_foo)
        self.assertIs(hooked.implementation, return_foo)
        self.assertEqual(hooked(), 'FOO')

    def test_w_unknown_kwarg(self):
        with self.assertRaises(TypeError):
            self._callFUT(nonesuch=42)

    def test_class(self):
        class C(object):
            pass

        hooked = self._callFUT(C)
        self.assertIsInstance(hooked(), C)

        hooked.sethook(return_bar)
        self.assertEqual(hooked(), 'BAR')

class TestIssue6Py(PyHookableMixin,
                   unittest.TestCase):
    # Make sphinx docs for hooked objects work.
    # https://github.com/zopefoundation/zope.hookable/issues/6
    # We need to proxy __doc__ to the original,
    # and synthesize an empty __bases__ and a __dict__ attribute
    # if they're not present.

    def _check_preserves_doc(self, docs):
        self.assertEqual("I have some docs", docs.__doc__)

        hooked = self._callFUT(docs)
        self.assertEqual(hooked.__doc__, docs.__doc__)

    def test_preserves_doc_function(self):
        def docs():
            """I have some docs"""
        self._check_preserves_doc(docs)

    def test_preserves_doc_class(self):
        class Docs(object):
            """I have some docs"""

        self._check_preserves_doc(Docs)

    def test_empty_bases_function(self):
        hooked = self._callFUT(return_foo)
        self.assertEqual((), hooked.__bases__)

    def test_empty_dict_function(self):
        hooked = self._callFUT(return_foo)
        self.assertEqual({}, hooked.__dict__)

    def test_bases_class(self):
        class C(object):
            pass
        self.assertEqual(C.__bases__, (object,))
        hooked = self._callFUT(C)
        self.assertEqual(hooked.__bases__, (object,))

    def test_dict_class(self):
        class C(object):
            pass

        hooked = self._callFUT(C)
        self.assertEqual(hooked.__dict__, C.__dict__)

    def test_non_string_attr_name(self):
        # Specifically for the C implementation, which has to deal with this
        hooked = self._callFUT(return_foo)
        with self.assertRaises(TypeError):
            getattr(hooked, 42)

        with self.assertRaises(TypeError):
            hooked.__getattribute__(42)

    def test_unicode_attribute_name(self):
        # Specifically for the C implementation, which has to deal with this
        hooked = self._callFUT(return_foo)
        result = hooked.__getattribute__(u'__bases__')
        self.assertEqual(result, ())

    def test_short_name(self):
        # Specifically for the C implementation, which has to deal with this
        hooked = self._callFUT(return_foo)
        with self.assertRaises(AttributeError):
            hooked.__getattribute__('')

class HookableTests(HookableMixin, PyHookableTests):
    pass

class TestIssue6(HookableMixin, TestIssue6Py):
    pass

def test_suite():
    return unittest.defaultTestLoader.loadTestsFromName(__name__)
