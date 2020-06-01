"""Tests for josepy.jwa."""
import unittest

import mock

from josepy import errors, test_util

RSA256_KEY = test_util.load_rsa_private_key('rsa256_key.pem')
RSA512_KEY = test_util.load_rsa_private_key('rsa512_key.pem')
RSA1024_KEY = test_util.load_rsa_private_key('rsa1024_key.pem')


class JWASignatureTest(unittest.TestCase):
    """Tests for josepy.jwa.JWASignature."""

    def setUp(self):
        from josepy.jwa import JWASignature

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
        from josepy.jwa import JWASignature
        from josepy.jwa import RS256
        self.assertTrue(JWASignature.from_json('RS256') is RS256)


class JWAHSTest(unittest.TestCase):  # pylint: disable=too-few-public-methods

    def test_it(self):
        from josepy.jwa import HS256
        sig = (
            b"\xceR\xea\xcd\x94\xab\xcf\xfb\xe0\xacA.:\x1a'\x08i\xe2\xc4"
            b"\r\x85+\x0e\x85\xaeUZ\xd4\xb3\x97zO"
        )
        self.assertEqual(HS256.sign(b'some key', b'foo'), sig)
        self.assertTrue(HS256.verify(b'some key', b'foo', sig) is True)
        self.assertTrue(HS256.verify(b'some key', b'foo', sig + b'!') is False)


class JWARSTest(unittest.TestCase):

    def test_sign_no_private_part(self):
        from josepy.jwa import RS256
        self.assertRaises(
            errors.Error, RS256.sign, RSA512_KEY.public_key(), b'foo')

    def test_sign_key_too_small(self):
        from josepy.jwa import RS256
        from josepy.jwa import PS256
        self.assertRaises(errors.Error, RS256.sign, RSA256_KEY, b'foo')
        self.assertRaises(errors.Error, PS256.sign, RSA256_KEY, b'foo')

    def test_rs(self):
        from josepy.jwa import RS256
        sig = (
            b'|\xc6\xb2\xa4\xab(\x87\x99\xfa*:\xea\xf8\xa0N&}\x9f\x0f\xc0O'
            b'\xc6t\xa3\xe6\xfa\xbb"\x15Y\x80Y\xe0\x81\xb8\x88)\xba\x0c\x9c'
            b'\xa4\x99\x1e\x19&\xd8\xc7\x99S\x97\xfc\x85\x0cOV\xe6\x07\x99'
            b'\xd2\xb9.>}\xfd'
        )
        self.assertEqual(RS256.sign(RSA512_KEY, b'foo'), sig)
        self.assertTrue(RS256.verify(RSA512_KEY.public_key(), b'foo', sig))
        self.assertFalse(RS256.verify(
            RSA512_KEY.public_key(), b'foo', sig + b'!'))

    def test_ps(self):
        from josepy.jwa import PS256
        sig = PS256.sign(RSA1024_KEY, b'foo')
        self.assertTrue(PS256.verify(RSA1024_KEY.public_key(), b'foo', sig))
        self.assertFalse(PS256.verify(
            RSA1024_KEY.public_key(), b'foo', sig + b'!'))

    def test_sign_new_api(self):
        from josepy.jwa import RS256
        key = mock.MagicMock()
        RS256.sign(key, "message")
        self.assertTrue(key.sign.called)

    def test_sign_old_api(self):
        from josepy.jwa import RS256
        key = mock.MagicMock(spec=[u'signer'])
        signer = mock.MagicMock()
        key.signer.return_value = signer
        RS256.sign(key, "message")
        self.assertTrue(all([
            key.signer.called,
            signer.update.called,
            signer.finalize.called]))

    def test_verify_new_api(self):
        from josepy.jwa import RS256
        key = mock.MagicMock()
        RS256.verify(key, "message", "signature")
        self.assertTrue(key.verify.called)

    def test_verify_old_api(self):
        from josepy.jwa import RS256
        key = mock.MagicMock(spec=[u'verifier'])
        verifier = mock.MagicMock()
        key.verifier.return_value = verifier
        RS256.verify(key, "message", "signature")
        self.assertTrue(all([
            key.verifier.called,
            verifier.update.called,
            verifier.verify.called]))


if __name__ == '__main__':
    unittest.main()  # pragma: no cover
