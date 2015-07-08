"""Tests for acme.jose.jwa."""
import os
import pkg_resources
import unittest

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from acme.jose import errors
from acme.jose import jwk_test


RSA1024_KEY = serialization.load_pem_private_key(
    pkg_resources.resource_string(
        __name__, os.path.join('testdata', 'rsa1024_key.pem')),
    password=None, backend=default_backend())


class JWASignatureTest(unittest.TestCase):
    """Tests for acme.jose.jwa.JWASignature."""

    def setUp(self):
        from acme.jose.jwa import JWASignature

        class MockSig(JWASignature):
            # pylint: disable=missing-docstring,too-few-public-methods
            # pylint: disable=abstract-class-not-used
            def sign(self, key, msg):
                raise NotImplementedError()  # pragma: no cover

            def verify(self, key, msg, sig):
                raise NotImplementedError()  # pragma: no cover

        # pylint: disable=invalid-name
        self.Sig1 = MockSig('Sig1')
        self.Sig2 = MockSig('Sig2')

    def test_eq(self):
        self.assertEqual(self.Sig1, self.Sig1)

    def test_ne(self):
        self.assertNotEqual(self.Sig1, self.Sig2)

    def test_ne_other_type(self):
        self.assertNotEqual(self.Sig1, 5)

    def test_repr(self):
        self.assertEqual('Sig1', repr(self.Sig1))
        self.assertEqual('Sig2', repr(self.Sig2))

    def test_to_partial_json(self):
        self.assertEqual(self.Sig1.to_partial_json(), 'Sig1')
        self.assertEqual(self.Sig2.to_partial_json(), 'Sig2')

    def test_from_json(self):
        from acme.jose.jwa import JWASignature
        from acme.jose.jwa import RS256
        self.assertTrue(JWASignature.from_json('RS256') is RS256)


class JWAHSTest(unittest.TestCase):  # pylint: disable=too-few-public-methods

    def test_it(self):
        from acme.jose.jwa import HS256
        sig = (
            "\xceR\xea\xcd\x94\xab\xcf\xfb\xe0\xacA.:\x1a'\x08i\xe2\xc4"
            "\r\x85+\x0e\x85\xaeUZ\xd4\xb3\x97zO"
        )
        self.assertEqual(HS256.sign('some key', 'foo'), sig)
        self.assertTrue(HS256.verify('some key', 'foo', sig) is True)
        self.assertTrue(HS256.verify('some key', 'foo', sig + '!') is False)


class JWARSTest(unittest.TestCase):

    def test_sign_no_private_part(self):
        from acme.jose.jwa import RS256
        self.assertRaises(
            errors.Error, RS256.sign, jwk_test.RSA512_KEY.public_key(), 'foo')

    def test_sign_key_too_small(self):
        from acme.jose.jwa import RS256
        from acme.jose.jwa import PS256
        self.assertRaises(errors.Error, RS256.sign, jwk_test.RSA256_KEY, 'foo')
        self.assertRaises(errors.Error, PS256.sign, jwk_test.RSA256_KEY, 'foo')

    def test_rs(self):
        from acme.jose.jwa import RS256
        sig = (
            '|\xc6\xb2\xa4\xab(\x87\x99\xfa*:\xea\xf8\xa0N&}\x9f\x0f\xc0O'
            '\xc6t\xa3\xe6\xfa\xbb"\x15Y\x80Y\xe0\x81\xb8\x88)\xba\x0c\x9c'
            '\xa4\x99\x1e\x19&\xd8\xc7\x99S\x97\xfc\x85\x0cOV\xe6\x07\x99'
            '\xd2\xb9.>}\xfd'
        )
        self.assertEqual(RS256.sign(jwk_test.RSA512_KEY, 'foo'), sig)
        self.assertTrue(RS256.verify(
            jwk_test.RSA512_KEY.public_key(), 'foo', sig))
        self.assertFalse(RS256.verify(
            jwk_test.RSA512_KEY.public_key(), 'foo', sig + '!'))

    def test_ps(self):
        from acme.jose.jwa import PS256
        sig = PS256.sign(RSA1024_KEY, 'foo')
        self.assertTrue(PS256.verify(RSA1024_KEY.public_key(), 'foo', sig))
        self.assertFalse(PS256.verify(RSA1024_KEY.public_key(), 'foo', sig + '!'))


if __name__ == '__main__':
    unittest.main()  # pragma: no cover
