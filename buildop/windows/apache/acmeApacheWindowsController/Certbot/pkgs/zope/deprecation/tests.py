import sys
import types
import unittest

class TestShowSwitch(unittest.TestCase):
    def _makeOne(self):
        from zope.deprecation import ShowSwitch
        return ShowSwitch()

    def test_on(self):
        switch = self._makeOne()
        switch.stack.append(False)
        switch.on()
        self.assertEqual(switch.stack, [])

    def test_off(self):
        switch = self._makeOne()
        switch.off()
        self.assertEqual(switch.stack, [False])

    def test_reset(self):
        switch = self._makeOne()
        switch.stack.append(False)
        switch.reset()
        self.assertEqual(switch.stack, [])

    def test_call_true(self):
        switch = self._makeOne()
        self.assertEqual(switch(), True)

    def test_call_false(self):
        switch = self._makeOne()
        switch.stack.append(False)
        self.assertEqual(switch(), False)

    def test_repr_on(self):
        switch = self._makeOne()
        self.assertEqual(repr(switch), '<ShowSwitch on>')

    def test_repr_off(self):
        switch = self._makeOne()
        switch.stack.append(False)
        self.assertEqual(repr(switch), '<ShowSwitch off>')

    def test___show__global(self):
        from zope.deprecation import __show__
        self.assertEqual(self._makeOne().__class__, __show__.__class__)

class TestSuppressor(unittest.TestCase):
    def _makeOne(self):
        from zope.deprecation import Suppressor
        return Suppressor()

    def test_it(self):
        from zope.deprecation import __show__
        self.assertEqual(__show__.stack, [])
        with self._makeOne():
            self.assertEqual(__show__.stack, [False])
        self.assertEqual(__show__.stack, [])

class WarningsSetupBase(object):
    def setUp(self):
        from zope.deprecation import deprecation
        self.oldwarnings = deprecation.warnings
        self.oldshow = deprecation.__show__
        self.warnings = DummyWarningsModule()
        self.show = DummyShow()
        deprecation.warnings = self.warnings
        deprecation.__show__ = self.show

    def tearDown(self):
        from zope.deprecation import deprecation
        deprecation.warnings = self.oldwarnings
        deprecation.__show__ = self.oldshow

class TestDeprecationProxy(WarningsSetupBase, unittest.TestCase):
    def _getTargetClass(self):
        from zope.deprecation.deprecation import DeprecationProxy
        return DeprecationProxy

    def _makeOne(self, module):
        cls = self._getTargetClass()
        return cls(module)

    def test_deprecate_and__getattribute__string(self):
        tests = _getTestsModule()
        proxy = self._makeOne(tests)
        proxy.deprecate('ClassFixture', 'hello')
        self.assertEqual(proxy.ClassFixture, ClassFixture)
        self.assertEqual(
            self.warnings.w,
            [('ClassFixture: hello', DeprecationWarning, 2)])

    def test_deprecate_and__getattribute__string_with_custom_cls(self):
        tests = _getTestsModule()
        proxy = self._makeOne(tests)
        proxy.deprecate('ClassFixture', 'hello', DummyWarning)
        self.assertEqual(proxy.ClassFixture, ClassFixture)
        self.assertEqual(
            self.warnings.w,
            [('ClassFixture: hello', DummyWarning, 2)])

    def test_deprecate_and__getattribute__sequence(self):
        tests = _getTestsModule()
        proxy = self._makeOne(tests)
        proxy.deprecate(('ClassFixture', 'ClassFixture2'), 'hello')
        self.assertEqual(proxy.ClassFixture, ClassFixture)
        self.assertEqual(proxy.ClassFixture2, ClassFixture2)
        self.assertEqual(
            self.warnings.w,
            [('ClassFixture: hello', DeprecationWarning, 2),
             ('ClassFixture2: hello', DeprecationWarning, 2)]
            )
    def test_deprecate_and__getattribute__noshow(self):
        tests = _getTestsModule()
        proxy = self._makeOne(tests)
        proxy.deprecate('ClassFixture', 'hello')
        self.show.on = False
        self.assertEqual(proxy.ClassFixture, ClassFixture)
        self.assertEqual(
            self.warnings.w, [])

    def test___getattribute____class__(self):
        tests = _getTestsModule()
        proxy = self._makeOne(tests)
        self.assertEqual(proxy.__class__, types.ModuleType)

    def test___getattribute___deprecate(self):
        tests = _getTestsModule()
        proxy = self._makeOne(tests)
        self.assertEqual(type(proxy.deprecate), types.MethodType)

    def test___getattribute__missing(self):
        tests = _getTestsModule()
        proxy = self._makeOne(tests)
        self.assertRaises(AttributeError, getattr, proxy, 'wontbethere')

    def test___setattr__owned(self):
        tests = _getTestsModule()
        proxy = self._makeOne(tests)
        proxy._DeprecationProxy__deprecated = {'foo':'bar'}
        self.assertEqual(proxy._DeprecationProxy__deprecated, {'foo':'bar'})

    def test___setattr__notowned(self):
        tests = _getTestsModule()
        proxy = self._makeOne(tests)
        try:
            proxy.foo = 'bar'
            self.assertEqual(tests.foo, 'bar')
        finally:
            del tests.foo

    def test___delattr__owned(self):
        tests = _getTestsModule()
        proxy = self._makeOne(tests)
        del proxy._DeprecationProxy__deprecated
        self.assertRaises(AttributeError, getattr, proxy,
                          '_DeprecationProxy__deprecated')

    def test___delattr__notowned(self):
        tests = _getTestsModule()
        proxy = self._makeOne(tests)
        tests.foo = 'bar'
        del proxy.foo
        self.assertRaises(AttributeError, getattr, tests, 'foo')

class TestDeprecatedModule(WarningsSetupBase, unittest.TestCase):
    def _getTargetClass(self):
        from zope.deprecation.deprecation import DeprecatedModule
        return DeprecatedModule

    def _makeOne(self, module, msg, *args):
        cls = self._getTargetClass()
        return cls(module, msg, *args)

    def test___getattribute____class__(self):
        tests = _getTestsModule()
        proxy = self._makeOne(tests, 'hello')
        self.assertEqual(proxy.__class__, types.ModuleType)

    def test___getattribute____owned__(self):
        tests = _getTestsModule()
        proxy = self._makeOne(tests, 'hello')
        self.assertEqual(proxy._DeprecatedModule__msg, 'hello')

    def test___getattribute___deprecated(self):
        tests = _getTestsModule()
        proxy = self._makeOne(tests, 'hello')
        self.assertEqual(proxy.ClassFixture, ClassFixture)
        self.assertEqual(
            self.warnings.w,
            [('hello', DeprecationWarning, 2)]
            )

    def test___getattribute___deprecated_with_custom_cls(self):
        tests = _getTestsModule()
        proxy = self._makeOne(tests, 'hello', DummyWarning)
        self.assertEqual(proxy.ClassFixture, ClassFixture)
        self.assertEqual(
            self.warnings.w,
            [('hello', DummyWarning, 2)]
            )

    def test___getattribute__missing(self):
        tests = _getTestsModule()
        proxy = self._makeOne(tests, 'hello')
        self.assertRaises(AttributeError, getattr, proxy, 'wontbethere')
        self.assertEqual(
            self.warnings.w,
            [('hello', DeprecationWarning, 2)]
            )

    def test___getattribute___noshow(self):
        tests = _getTestsModule()
        self.show.on = False
        proxy = self._makeOne(tests, 'hello')
        self.assertEqual(proxy.ClassFixture, ClassFixture)
        self.assertEqual(
            self.warnings.w, [])

    def test___setattr__owned(self):
        tests = _getTestsModule()
        proxy = self._makeOne(tests, 'hello')
        proxy._DeprecatedModule__msg = 'foo'
        self.assertEqual(proxy._DeprecatedModule__msg, 'foo')

    def test___setattr__notowned(self):
        tests = _getTestsModule()
        proxy = self._makeOne(tests, 'hello')
        try:
            proxy.foo = 'bar'
            self.assertEqual(tests.foo, 'bar')
        finally:
            del tests.foo

    def test___delattr__owned(self):
        tests = _getTestsModule()
        proxy = self._makeOne(tests, 'hello')
        del proxy._DeprecatedModule__msg
        self.assertRaises(AttributeError, getattr, proxy,
                          '_DeprecatedModule__msg')

    def test___delattr__notowned(self):
        tests = _getTestsModule()
        proxy = self._makeOne(tests, 'hello')
        tests.foo = 'bar'
        del proxy.foo
        self.assertRaises(AttributeError, getattr, tests, 'foo')

class TestDeprecatedGetProperty(WarningsSetupBase, unittest.TestCase):
    def _getTargetClass(self):
        from zope.deprecation.deprecation import DeprecatedGetProperty
        return DeprecatedGetProperty

    def _makeOne(self, prop, msg, *args):
        cls = self._getTargetClass()
        return cls(prop, msg, *args)

    def test___get__(self):
        prop = DummyProperty()
        proxy = self._makeOne(prop, 'hello')
        self.assertEqual(proxy.__get__('inst', 'cls'), None)
        self.assertEqual(prop.inst, 'inst')
        self.assertEqual(prop.cls, 'cls')
        self.assertEqual(
            self.warnings.w,
            [('hello', DeprecationWarning, 2)]
            )

    def test___get___with_custom_cls(self):
        prop = DummyProperty()
        proxy = self._makeOne(prop, 'hello', DummyWarning)
        self.assertEqual(proxy.__get__('inst', 'cls'), None)
        self.assertEqual(prop.inst, 'inst')
        self.assertEqual(prop.cls, 'cls')
        self.assertEqual(
            self.warnings.w,
            [('hello', DummyWarning, 2)]
            )

    def test___get__noshow(self):
        prop = DummyProperty()
        self.show.on = False
        proxy = self._makeOne(prop, 'hello')
        self.assertEqual(proxy.__get__('inst', 'cls'), None)
        self.assertEqual(prop.inst, 'inst')
        self.assertEqual(prop.cls, 'cls')
        self.assertEqual(self.warnings.w, [])

class TestDeprecatedGetSetProperty(TestDeprecatedGetProperty):
    def _getTargetClass(self):
        from zope.deprecation.deprecation import DeprecatedGetSetProperty
        return DeprecatedGetSetProperty

    def test___set__(self):
        prop = DummyProperty()
        proxy = self._makeOne(prop, 'hello')
        self.assertEqual(proxy.__set__('inst', 'prop'), None)
        self.assertEqual(prop.inst, 'inst')
        self.assertEqual(prop.prop, 'prop')
        self.assertEqual(
            self.warnings.w,
            [('hello', DeprecationWarning, 2)]
            )

    def test___set___with_custom_cls(self):
        prop = DummyProperty()
        proxy = self._makeOne(prop, 'hello', DummyWarning)
        self.assertEqual(proxy.__set__('inst', 'prop'), None)
        self.assertEqual(prop.inst, 'inst')
        self.assertEqual(prop.prop, 'prop')
        self.assertEqual(
            self.warnings.w,
            [('hello', DummyWarning, 2)]
            )

    def test___set__noshow(self):
        prop = DummyProperty()
        self.show.on = False
        proxy = self._makeOne(prop, 'hello')
        self.assertEqual(proxy.__set__('inst', 'prop'), None)
        self.assertEqual(prop.inst, 'inst')
        self.assertEqual(prop.prop, 'prop')
        self.assertEqual(self.warnings.w, [])

class TestDeprecatedSetGetDeleteProperty(TestDeprecatedGetSetProperty):
    def _getTargetClass(self):
        from zope.deprecation.deprecation import DeprecatedGetSetDeleteProperty
        return DeprecatedGetSetDeleteProperty

    def test___delete__(self):
        prop = DummyProperty()
        proxy = self._makeOne(prop, 'hello')
        self.assertEqual(proxy.__delete__('inst'), None)
        self.assertEqual(prop.inst, 'inst')
        self.assertEqual(
            self.warnings.w,
            [('hello', DeprecationWarning, 2)]
            )

    def test___delete___with_custom_cls(self):
        prop = DummyProperty()
        proxy = self._makeOne(prop, 'hello', DummyWarning)
        self.assertEqual(proxy.__delete__('inst'), None)
        self.assertEqual(prop.inst, 'inst')
        self.assertEqual(
            self.warnings.w,
            [('hello', DummyWarning, 2)]
            )

    def test___delete__noshow(self):
        prop = DummyProperty()
        proxy = self._makeOne(prop, 'hello')
        self.assertEqual(proxy.__delete__('inst'), None)
        self.assertEqual(prop.inst, 'inst')
        self.assertEqual(
            self.warnings.w,
            [('hello', DeprecationWarning, 2)]
            )

class TestDeprecatedMethod(WarningsSetupBase, unittest.TestCase):
    def _callFUT(self, method, message, *args):
        from zope.deprecation.deprecation import DeprecatedMethod
        return DeprecatedMethod(method, message, *args)

    def fixture(self, a, b, c=1):
        return 'fixture'

    def test_it(self):
        result = self._callFUT(self.fixture, 'hello')
        self.assertEqual(result('a', 'b', c=2), 'fixture')
        self.assertEqual(
            self.warnings.w,
            [('hello', DeprecationWarning, 2)]
            )

    def test_it_with_custom_cls(self):
        result = self._callFUT(self.fixture, 'hello', DummyWarning)
        self.assertEqual(result('a', 'b', c=2), 'fixture')
        self.assertEqual(
            self.warnings.w,
            [('hello', DummyWarning, 2)]
            )

    def test_it_noshow(self):
        result = self._callFUT(self.fixture, 'hello')
        self.show.on = False
        self.assertEqual(result('a', 'b', c=2), 'fixture')
        self.assertEqual(self.warnings.w, [])

class Test_deprecated(WarningsSetupBase, unittest.TestCase):
    def setUp(self):
        super(Test_deprecated, self).setUp()
        self.mod = _getTestsModule()

    def tearDown(self):
        super(Test_deprecated, self).tearDown()
        sys.modules['zope.deprecation.tests'] = self.mod

    def _callFUT(self, spec, message, *args):
        from zope.deprecation.deprecation import deprecated
        return deprecated(spec, message, *args)

    def test_string_specifier(self):
        self._callFUT('ClassFixture', 'hello')
        mod = _getTestsModule()
        self.assertNotEqual(mod, self.mod)
        self.assertEqual(mod.ClassFixture, ClassFixture)
        self.assertEqual(
            self.warnings.w,
            [('ClassFixture: hello', DeprecationWarning, 2)])

    def test_string_specifier_with_custom_cls(self):
        self._callFUT('ClassFixture', 'hello', DummyWarning)
        mod = _getTestsModule()
        self.assertNotEqual(mod, self.mod)
        self.assertEqual(mod.ClassFixture, ClassFixture)
        self.assertEqual(
            self.warnings.w,
            [('ClassFixture: hello', DummyWarning, 2)])

    def test_string_specifier_sys_modules_already_mutated(self):
        from zope.deprecation.deprecation import DeprecationProxy
        mod = _getTestsModule()
        new = sys.modules['zope.deprecation.tests'] = DeprecationProxy(mod)
        self._callFUT('ClassFixture', 'hello')
        self.assertEqual(new.ClassFixture, ClassFixture)
        self.assertEqual(
            self.warnings.w,
            [('ClassFixture: hello', DeprecationWarning, 2)])

    def test_function_specifier(self):
        result = self._callFUT(functionfixture, 'hello')
        self.assertNotEqual(result, functionfixture)
        self.assertEqual(self.warnings.w, [])
        result()
        self.assertEqual(
            self.warnings.w,
            [('hello', DeprecationWarning, 2)])

    def test_module_specifier(self):
        mod = _getTestsModule()
        result = self._callFUT(mod, 'hello')
        self.assertEqual(self.warnings.w, [])
        self.assertEqual(result.ClassFixture, ClassFixture)
        self.assertEqual(
            self.warnings.w,
            [('hello', DeprecationWarning, 2)])

    def test_getproperty_specifier(self):
        prop = DummyGetProperty()
        result = self._callFUT(prop, 'hello')
        self.assertEqual(self.warnings.w, [])
        self.assertEqual(result.__get__('inst', 'cls'), None)
        self.assertEqual(
            self.warnings.w,
            [('hello', DeprecationWarning, 2)])

    def test_getsetproperty_specifier(self):
        prop = DummyGetSetProperty()
        result = self._callFUT(prop, 'hello')
        self.assertEqual(self.warnings.w, [])
        self.assertEqual(result.__set__('inst', 'prop'), None)
        self.assertEqual(
            self.warnings.w,
            [('hello', DeprecationWarning, 2)])

    def test_getsetdeleteproperty_specifier(self):
        prop = DummyGetSetDeleteProperty()
        result = self._callFUT(prop, 'hello')
        self.assertEqual(self.warnings.w, [])
        self.assertEqual(result.__delete__('inst'), None)
        self.assertEqual(
            self.warnings.w,
            [('hello', DeprecationWarning, 2)])

class Test_deprecate(WarningsSetupBase, unittest.TestCase):
    def _getTargetClass(self):
        from zope.deprecation.deprecation import deprecate
        return deprecate

    def _makeOne(self, msg, *args):
        cls = self._getTargetClass()
        return cls(msg, *args)

    def fixture(self):
        return 42

    def test___call__(self):
        proxy = self._makeOne('hello')
        result = proxy(functionfixture)
        self.assertEqual(result(), None)
        self.assertEqual(
            self.warnings.w,
            [('hello', DeprecationWarning, 2)])

    def test___call__method(self):
        proxy = self._makeOne('method')
        result = proxy(self.fixture)
        self.assertEqual(result(), 42)
        self.assertEqual(
            self.warnings.w,
            [('method', DeprecationWarning, 2)])

    def test___call__with_custom_cls(self):
        proxy = self._makeOne('hello', DummyWarning)
        result = proxy(functionfixture)
        self.assertEqual(result(), None)
        self.assertEqual(
            self.warnings.w,
            [('hello', DummyWarning, 2)])

class Test_moved(WarningsSetupBase, unittest.TestCase):
    def setUp(self):
        super(Test_moved, self).setUp()

    def tearDown(self):
        super(Test_moved, self).tearDown()
        del _getTestsModule().__dict__['abc']

    def _callFUT(self, to_location, unsupported_in, *args):
        from zope.deprecation.deprecation import moved
        return moved(to_location, unsupported_in, *args)

    def test_unsupported_None(self):
        self._callFUT('zope.deprecation.fixture', None)
        self.assertEqual(
            self.warnings.w,
             [('zope.deprecation.tests has moved to zope.deprecation.fixture.',
               DeprecationWarning, 3)])

    def test_unsupported_None_with_custom_cls(self):
        self._callFUT('zope.deprecation.fixture', None, DummyWarning)
        self.assertEqual(
            self.warnings.w,
             [('zope.deprecation.tests has moved to zope.deprecation.fixture.',
               DummyWarning, 3)])

    def test_unsupported_not_None(self):
        self._callFUT('zope.deprecation.fixture', '1.3')
        self.assertEqual(
            self.warnings.w,
            [('zope.deprecation.tests has moved to zope.deprecation.fixture. '
              'Import of zope.deprecation.tests will become unsupported in 1.3',
              DeprecationWarning, 3)])

class Test_import_aliases(unittest.TestCase):
    def test_it(self):
        for name in ('deprecated', 'deprecate', 'moved', 'ShowSwitch',
                     '__show__'):
            real = getattr(sys.modules['zope.deprecation.deprecation'], name)
            alias = getattr(sys.modules['zope.deprecation'], name)
            self.assertEqual(real, alias, (real, alias))

class DummyWarningsModule(object):
    def __init__(self):
        self.w = []

    def warn(self, msg, type, stacklevel):
        self.w.append((msg, type, stacklevel))

class DummyGetProperty(object):
    def __get__(self, inst, cls):
        self.inst = inst
        self.cls = cls

class DummyGetSetProperty(DummyGetProperty):
    def __set__(self, inst, prop):
        self.inst = inst
        self.prop = prop

class DummyGetSetDeleteProperty(DummyGetSetProperty):
    def __delete__(self, inst):
        self.inst = inst

class DummyWarning(DeprecationWarning):
    pass

DummyProperty = DummyGetSetDeleteProperty

def _getTestsModule():
    __import__('zope.deprecation.tests')
    return sys.modules['zope.deprecation.tests']

class DummyShow(object):
    def __init__(self):
        self.on = True

    def __call__(self):
        if self.on:
            return True
        return False

class ClassFixture(object): pass

class ClassFixture2(object): pass

def functionfixture(): pass
