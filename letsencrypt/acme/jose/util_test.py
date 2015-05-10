"""Tests for letsencrypt.acme.jose.util."""
import functools
import os
import pkg_resources
import unittest

import Crypto.PublicKey.RSA


class HashableRSAKeyTest(unittest.TestCase):
    """Tests for letsencrypt.acme.jose.util.HashableRSAKey."""

    def setUp(self):
        from letsencrypt.acme.jose.util import HashableRSAKey
        self.key = HashableRSAKey(Crypto.PublicKey.RSA.importKey(
            pkg_resources.resource_string(
                __name__, os.path.join('testdata', 'rsa256_key.pem'))))
        self.key_same = HashableRSAKey(Crypto.PublicKey.RSA.importKey(
            pkg_resources.resource_string(
                __name__, os.path.join('testdata', 'rsa256_key.pem'))))

    def test_eq(self):
        # if __eq__ is not defined, then two HashableRSAKeys with same
        # _wrapped do not equate
        self.assertEqual(self.key, self.key_same)

    def test_hash(self):
        self.assertTrue(isinstance(hash(self.key), int))

    def test_publickey(self):
        from letsencrypt.acme.jose.util import HashableRSAKey
        self.assertTrue(isinstance(self.key.publickey(), HashableRSAKey))


class ImmutableMapTest(unittest.TestCase):
    """Tests for letsencrypt.acme.jose.util.ImmutableMap."""

    def setUp(self):
        # pylint: disable=invalid-name,too-few-public-methods
        # pylint: disable=missing-docstring
        from letsencrypt.acme.jose.util import ImmutableMap

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

    def test_update(self):
        self.assertEqual(self.A(x=2, y=2), self.a1.update(x=2))
        self.assertEqual(self.a2, self.a1.update(x=3, y=4))

    def test_get_missing_item_raises_key_error(self):
        self.assertRaises(KeyError, self.a1.__getitem__, 'z')

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

    def test_hash(self):
        self.assertEqual(hash((1, 2)), hash(self.a1))

    def test_unhashable(self):
        self.assertRaises(TypeError, self.A(x=1, y={}).__hash__)

    def test_repr(self):
        self.assertEqual('A(x=1, y=2)', repr(self.a1))
        self.assertEqual('A(x=1, y=2)', repr(self.a1_swap))
        self.assertEqual('B(x=1, y=2)', repr(self.b))
        self.assertEqual("B(x='foo', y='bar')", repr(self.B(x='foo', y='bar')))


class frozendictTest(unittest.TestCase):  # pylint: disable=invalid-name
    """Tests for letsencrypt.acme.jose.util.frozendict."""

    def setUp(self):
        from letsencrypt.acme.jose.util import frozendict
        self.fdict = frozendict(x=1, y='2')

    def test_init_dict(self):
        from letsencrypt.acme.jose.util import frozendict
        self.assertEqual(self.fdict, frozendict({'x': 1, 'y': '2'}))

    def test_init_other_raises_type_error(self):
        from letsencrypt.acme.jose.util import frozendict
        # specifically fail for generators...
        self.assertRaises(TypeError, frozendict, {'a': 'b'}.iteritems())

    def test_len(self):
        self.assertEqual(2, len(self.fdict))

    def test_hash(self):
        self.assertEqual(1278944519403861804, hash(self.fdict))

    def test_getattr_proxy(self):
        self.assertEqual(1, self.fdict.x)
        self.assertEqual('2', self.fdict.y)

    def test_getattr_raises_attribute_error(self):
        self.assertRaises(AttributeError, self.fdict.__getattr__, 'z')

    def test_setattr_immutable(self):
        self.assertRaises(AttributeError, self.fdict.__setattr__, 'z', 3)

    def test_repr(self):
        self.assertEqual("frozendict(x=1, y='2')", repr(self.fdict))


if __name__ == '__main__':
    unittest.main()  # pragma: no cover
