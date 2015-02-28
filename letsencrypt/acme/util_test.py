"""Tests for letsencrypt.acme.util."""
import functools
import json
import unittest

import zope.interface

from letsencrypt.acme import errors
from letsencrypt.acme import interfaces


class MockJSONSerialiazable(object):
    # pylint: disable=missing-docstring,too-few-public-methods,no-self-use
    zope.interface.implements(interfaces.IJSONSerializable)

    def to_json(self):
        return [3, 2, 1]


class JSONDeSerializableTest(unittest.TestCase):
    """Tests for letsencrypt.acme.util.JSONDeSerializable."""

    def setUp(self):
        from letsencrypt.acme.util import JSONDeSerializable

        class Tester(JSONDeSerializable):
            # pylint: disable=missing-docstring,no-self-use,
            # pylint: disable=too-few-public-methods
            zope.interface.implements(interfaces.IJSONSerializable)

            schema = {'type': 'integer'}

            def __init__(self, jobj):
                self.jobj = jobj

            @classmethod
            def _from_valid_json(cls, jobj):
                return cls(jobj)

            def to_json(self):
                return {'foo': MockJSONSerialiazable()}

        self.tester_cls = Tester

    def test_validate_invalid_json(self):
        self.assertRaises(errors.SchemaValidationError,
                          self.tester_cls.validate_json, 'bang!')

    def test_validate_valid_json(self):
        self.tester_cls.validate_json(5)

    def test_from_json(self):
        self.assertEqual(5, self.tester_cls.from_json(5, validate=True).jobj)

    def test_from_json_no_validation(self):
        self.assertEqual(['1', 2], self.tester_cls.from_json(
            ['1', 2], validate=False).jobj)

    def test_from_valid_json_raises_error(self):
        from letsencrypt.acme.util import JSONDeSerializable
        # pylint: disable=protected-access
        self.assertRaises(
            NotImplementedError, JSONDeSerializable._from_valid_json, 'foo')

    def test_json_loads(self):
        tester = self.tester_cls.json_loads('5', validate=True)
        self.assertEqual(tester.jobj, 5)

    def test_json_loads_no_validation(self):
        self.assertEqual(
            'foo', self.tester_cls.json_loads('"foo"', validate=False).jobj)

    def test_to_json_raises_error(self):
        from letsencrypt.acme.util import JSONDeSerializable
        self.assertRaises(NotImplementedError, JSONDeSerializable().to_json)

    def test_json_dumps(self):
        self.assertEqual(
            self.tester_cls('foo').json_dumps(), '{"foo": [3, 2, 1]}')


class DumpIJSONSerializableTest(unittest.TestCase):
    """Tests for letsencrypt.acme.util.dump_ijsonserializable."""

    @classmethod
    def _call(cls, obj):
        from letsencrypt.acme.util import dump_ijsonserializable
        return json.dumps(obj, default=dump_ijsonserializable)

    def test_json_type(self):
        self.assertEqual('5', self._call(5))

    def test_ijsonserializable(self):
        self.assertEqual('[3, 2, 1]', self._call(MockJSONSerialiazable()))

    def test_raises_type_error(self):
        self.assertRaises(TypeError, self._call, object())


class ImmutableMapTest(unittest.TestCase):
    """Tests for letsencrypt.acme.util.ImmutableMap."""

    def setUp(self):
        # pylint: disable=invalid-name,too-few-public-methods
        # pylint: disable=missing-docstring
        from letsencrypt.acme.util import ImmutableMap

        class A(ImmutableMap):
            __slots__ = ('x', 'y')

        class B(ImmutableMap):
            __slots__ = ('x', 'y')

        self.A = A
        self.B = B

        self.a1 = self.A(x=1, y=2)
        self.a1_swap = self.A(y=2, x=1)
        self.a2 = self.A(x=3, y=4)
        self.b = self.B(x=1, y=2)

    def test_order_of_args_does_not_matter(self):
        self.assertEqual(self.a1, self.a1_swap)

    def test_type_error_on_missing(self):
        self.assertRaises(TypeError, self.A, x=1)
        self.assertRaises(TypeError, self.A, y=2)

    def test_type_error_on_unrecognized(self):
        self.assertRaises(TypeError, self.A, x=1, z=2)
        self.assertRaises(TypeError, self.A, x=1, y=2, z=3)

    def test_get_attr(self):
        self.assertEqual(1, self.a1.x)
        self.assertEqual(2, self.a1.y)
        self.assertEqual(1, self.a1_swap.x)
        self.assertEqual(2, self.a1_swap.y)

    def test_set_attr_raises_attribute_error(self):
        self.assertRaises(
            AttributeError, functools.partial(self.a1.__setattr__, 'x'), 10)

    def test_equal(self):
        self.assertEqual(self.a1, self.a1)
        self.assertEqual(self.a2, self.a2)
        self.assertNotEqual(self.a1, self.a2)

    def test_same_slots_diff_cls_not_equal(self):
        self.assertEqual(self.a1.x, self.b.x)
        self.assertEqual(self.a1.y, self.b.y)
        self.assertNotEqual(self.a1, self.b)

    def test_hash(self):
        self.assertEqual(hash((1, 2)), hash(self.a1))

    def test_unhashable(self):
        self.assertRaises(TypeError, self.A(x=1, y={}).__hash__)

    def test_repr(self):
        self.assertEqual('A(x=1, y=2)', repr(self.a1))
        self.assertEqual('A(x=1, y=2)', repr(self.a1_swap))
        self.assertEqual('B(x=1, y=2)', repr(self.b))
        self.assertEqual("B(x='foo', y='bar')", repr(self.B(x='foo', y='bar')))


if __name__ == '__main__':
    unittest.main()
