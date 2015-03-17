"""Tests for letsencrypt.acme.jose.jwa."""
import os
import pkg_resources
import unittest

from Crypto.PublicKey import RSA

from letsencrypt.acme.jose import errors


RSA256_KEY = RSA.importKey(pkg_resources.resource_string(
    __name__, os.path.join('testdata', 'rsa256_key.pem')))
RSA512_KEY = RSA.importKey(pkg_resources.resource_string(
    __name__, os.path.join('testdata', 'rsa512_key.pem')))
RSA1024_KEY = RSA.importKey(pkg_resources.resource_string(
    __name__, os.path.join('testdata', 'rsa1024_key.pem')))


class JWASignatureTest(unittest.TestCase):
    """Tests for letsencrypt.acme.jose.jwa.JWASignature."""

    def setUp(self):
        from letsencrypt.acme.jose.jwa import JWASignature

        class MockSig(JWASignature):
            # pylint: disable=missing-docstring,too-few-public-methods
            # pylint: disable=abstract-class-not-used
            def sign(self, key, msg):
                raise NotImplementedError()

            def verify(self, key, msg, sig):
                raise NotImplementedError()

        # pylint: disable=invalid-name
        self.Sig1 = MockSig('Sig1')
        self.Sig2 = MockSig('Sig2')

    def test_eq(self):
        self.assertEqual(self.Sig1, self.Sig1)
        self.assertNotEqual(self.Sig1, self.Sig2)

    def test_repr(self):
        self.assertEqual('Sig1', repr(self.Sig1))
        self.assertEqual('Sig2', repr(self.Sig2))

    def test_to_json(self):
        self.assertEqual(self.Sig1.to_json(), 'Sig1')
        self.assertEqual(self.Sig2.to_json(), 'Sig2')

    def test_from_json(self):
        from letsencrypt.acme.jose.jwa import JWASignature
        from letsencrypt.acme.jose.jwa import RS256
        self.assertTrue(JWASignature.from_json('RS256') is RS256)


class JWAHSTest(unittest.TestCase):  # pylint: disable=too-few-public-methods

    def test_it(self):
        from letsencrypt.acme.jose.jwa import HS256
        sig = (
            "\xceR\xea\xcd\x94\xab\xcf\xfb\xe0\xacA.:\x1a'\x08i\xe2\xc4"
            "\r\x85+\x0e\x85\xaeUZ\xd4\xb3\x97zO"
        )
        self.assertEqual(HS256.sign('some key', 'foo'), sig)
        self.assertTrue(HS256.verify('some key', 'foo', sig) is True)
        self.assertTrue(HS256.verify('some key', 'foo', sig + '!') is False)


class JWARSTest(unittest.TestCase):

    def test_sign_no_private_part(self):
        from letsencrypt.acme.jose.jwa import RS256
        self.assertRaises(
            errors.Error, RS256.sign, RSA512_KEY.publickey(), 'foo')

    def test_sign_key_too_small(self):
        from letsencrypt.acme.jose.jwa import RS256
        from letsencrypt.acme.jose.jwa import PS256
        self.assertRaises(errors.Error, RS256.sign, RSA256_KEY, 'foo')
        self.assertRaises(errors.Error, PS256.sign, RSA256_KEY, 'foo')
        self.assertRaises(errors.Error, PS256.sign, RSA512_KEY, 'foo')

    def test_rs(self):
        from letsencrypt.acme.jose.jwa import RS256
        sig = (
            '\x13\xf0\xe5\x83\x91\xd8~\x02q\xdf\xbdwX\x97\xecn\xe4UH\xb0'
            '\xe1oq\x94\x9f\xf4\x0f\xcb0\x05\xa9\x0fs\xea\xf3\xe3\xe7'
            '\x1cAh\xb3@\xb8\xe4UnG\xa0\xb2K\xac-\x1c1\x1c\xe9dw}2@\xa7'
            '\xf0\xe8'
        )
        self.assertEqual(RS256.sign(RSA512_KEY, 'foo'), sig)
        # next tests guard that only True/False are return as oppossed
        # to e.g. 1/0
        self.assertTrue(RS256.verify(RSA512_KEY, 'foo', sig) is True)
        self.assertFalse(RS256.verify(RSA512_KEY, 'foo', sig + '!') is False)

    def test_ps(self):
        from letsencrypt.acme.jose.jwa import PS256
        sig = PS256.sign(RSA1024_KEY, 'foo')
        self.assertTrue(PS256.verify(RSA1024_KEY, 'foo', sig) is True)
        self.assertTrue(PS256.verify(RSA1024_KEY, 'foo', sig + '!') is False)


if __name__ == '__main__':
    unittest.main()
