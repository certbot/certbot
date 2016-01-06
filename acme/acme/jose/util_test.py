"""Tests for acme.jose.util."""
import functools
import unittest

import six

from acme import test_util


class ComparableX509Test(unittest.TestCase):
    """Tests for acme.jose.util.ComparableX509."""

    def setUp(self):
        # test_util.load_comparable_{csr,cert} return ComparableX509
        self.req1 = test_util.load_comparable_csr('csr.pem')
        self.req2 = test_util.load_comparable_csr('csr.pem')
        self.req_other = test_util.load_comparable_csr('csr-san.pem')

        self.cert1 = test_util.load_comparable_cert('cert.pem')
        self.cert2 = test_util.load_comparable_cert('cert.pem')
        self.cert_other = test_util.load_comparable_cert('cert-san.pem')

    def test_getattr_proxy(self):
        self.assertTrue(self.cert1.has_expired())

    def test_eq(self):
        self.assertEqual(self.req1, self.req2)
        self.assertEqual(self.cert1, self.cert2)

    def test_ne(self):
        self.assertNotEqual(self.req1, self.req_other)
        self.assertNotEqual(self.cert1, self.cert_other)

    def test_ne_wrong_types(self):
        self.assertNotEqual(self.req1, 5)
        self.assertNotEqual(self.cert1, 5)

    def test_hash(self):
        self.assertEqual(hash(self.req1), hash(self.req2))
        self.assertNotEqual(hash(self.req1), hash(self.req_other))

        self.assertEqual(hash(self.cert1), hash(self.cert2))
        self.assertNotEqual(hash(self.cert1), hash(self.cert_other))

    def test_repr(self):
        for x509 in self.req1, self.cert1:
            self.assertEqual(repr(x509),
                             '<ComparableX509({0!r})>'.format(x509.wrapped))


class ComparableRSAKeyTest(unittest.TestCase):
    """Tests for acme.jose.util.ComparableRSAKey."""

    def setUp(self):
        # test_utl.load_rsa_private_key return ComparableRSAKey
        self.key = test_util.load_rsa_private_key('rsa256_key.pem')
        self.key_same = test_util.load_rsa_private_key('rsa256_key.pem')
        self.key2 = test_util.load_rsa_private_key('rsa512_key.pem')

    def test_getattr_proxy(self):
        self.assertEqual(256, self.key.key_size)

    def test_eq(self):
        self.assertEqual(self.key, self.key_same)

    def test_ne(self):
        self.assertNotEqual(self.key, self.key2)

    def test_ne_different_types(self):
        self.assertNotEqual(self.key, 5)

    def test_ne_not_wrapped(self):
        # pylint: disable=protected-access
        self.assertNotEqual(self.key, self.key_same._wrapped)

    def test_ne_no_serialization(self):
        from acme.jose.util import ComparableRSAKey
        self.assertNotEqual(ComparableRSAKey(5), ComparableRSAKey(5))

    def test_hash(self):
        self.assertTrue(isinstance(hash(self.key), int))
        self.assertEqual(hash(self.key), hash(self.key_same))
        self.assertNotEqual(hash(self.key), hash(self.key2))

    def test_repr(self):
        self.assertTrue(repr(self.key).startswith(
            '<ComparableRSAKey(<cryptography.hazmat.'))

    def test_public_key(self):
        from acme.jose.util import ComparableRSAKey
        self.assertTrue(isinstance(self.key.public_key(), ComparableRSAKey))


class ImmutableMapTest(unittest.TestCase):
    """Tests for acme.jose.util.ImmutableMap."""

    def setUp(self):
        # pylint: disable=invalid-name,too-few-public-methods
        # pylint: disable=missing-docstring
        from acme.jose.util import ImmutableMap

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
    """Tests for acme.jose.util.frozendict."""

    def setUp(self):
        from acme.jose.util import frozendict
        self.fdict = frozendict(x=1, y='2')

    def test_init_dict(self):
        from acme.jose.util import frozendict
        self.assertEqual(self.fdict, frozendict({'x': 1, 'y': '2'}))

    def test_init_other_raises_type_error(self):
        from acme.jose.util import frozendict
        # specifically fail for generators...
        self.assertRaises(TypeError, frozendict, six.iteritems({'a': 'b'}))

    def test_len(self):
        self.assertEqual(2, len(self.fdict))

    def test_hash(self):
        self.assertTrue(isinstance(hash(self.fdict), int))

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
