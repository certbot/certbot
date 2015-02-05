"""Tests for letsencrypt.acme.jose."""
import pkg_resources
import unittest

import Crypto.PublicKey.RSA


RSA256_KEY = Crypto.PublicKey.RSA.importKey(pkg_resources.resource_string(
    'letsencrypt.client.tests', 'testdata/rsa256_key.pem'))
RSA512_KEY = Crypto.PublicKey.RSA.importKey(pkg_resources.resource_string(
    'letsencrypt.client.tests', 'testdata/rsa512_key.pem'))


class JWKTest(unittest.TestCase):
    """Tests fro letsencrypt.acme.jose.JWK."""

    def setUp(self):
        from letsencrypt.acme.jose import JWK
        self.jwk256 = JWK(RSA256_KEY.publickey())
        self.jwk256json = {
            'kty': 'RSA',
            'e': 'AQAB',
            'n': 'rHVztFHtH92ucFJD_N_HW9AsdRsUuHUBBBDlHwNlRd3fp5'
                 '80rv2-6QWE30cWgdmJS86ObRz6lUTor4R0T-3C5Q',
        }
        self.jwk512 = JWK(RSA512_KEY.publickey())
        self.jwk512json = {
            'kty': 'RSA',
            'e': 'AQAB',
            'n': '9LYRcVE3Nr-qleecEcX8JwVDnjeG1X7ucsCasuuZM0e09c'
                 'mYuUzxIkMjO_9x4AVcvXXRXPEV-LzWWkfkTlzRMw',
        }

    def test_equals(self):
        self.assertEqual(self.jwk256, self.jwk256)
        self.assertEqual(self.jwk512, self.jwk512)

    def test_not_equals(self):
        self.assertNotEqual(self.jwk256, self.jwk512)
        self.assertNotEqual(self.jwk512, self.jwk256)

    def test_equals_raises_type_error(self):
        self.assertRaises(TypeError, self.jwk256.__eq__, 123)

    def test_to_json(self):
        self.assertEqual(self.jwk256.to_json(), self.jwk256json)
        self.assertEqual(self.jwk512.to_json(), self.jwk512json)

    def test_from_json(self):
        from letsencrypt.acme.jose import JWK
        self.assertEqual(self.jwk256, JWK.from_json(self.jwk256json))
        self.assertEqual(self.jwk512, JWK.from_json(self.jwk512json))


# https://en.wikipedia.org/wiki/Base64#Examples
B64_PADDING_EXAMPLES = {
    'any carnal pleasure.': ('YW55IGNhcm5hbCBwbGVhc3VyZS4', '='),
    'any carnal pleasure': ('YW55IGNhcm5hbCBwbGVhc3VyZQ', '=='),
    'any carnal pleasur': ('YW55IGNhcm5hbCBwbGVhc3Vy', ''),
    'any carnal pleasu': ('YW55IGNhcm5hbCBwbGVhc3U', '='),
    'any carnal pleas': ('YW55IGNhcm5hbCBwbGVhcw', '=='),
}


B64_URL_UNSAFE_EXAMPLES = {
    chr(251) + chr(239): '--8',
    chr(255) * 2: '__8',
}


class B64EncodeTest(unittest.TestCase):
    """Tests for letsencrypt.acme.jose.b64encode."""

    @classmethod
    def _call(cls, data):
        from letsencrypt.acme.jose import b64encode
        return b64encode(data)

    def test_unsafe_url(self):
        for text, b64 in B64_URL_UNSAFE_EXAMPLES.iteritems():
            self.assertEqual(self._call(text), b64)

    def test_different_paddings(self):
        for text, (b64, _) in B64_PADDING_EXAMPLES.iteritems():
            self.assertEqual(self._call(text), b64)

    def test_unicode_fails_with_type_error(self):
        self.assertRaises(TypeError, self._call, u'some unicode')


class B64DecodeTest(unittest.TestCase):
    """Tests for letsencrypt.acme.jose.b64decode."""

    @classmethod
    def _call(cls, data):
        from letsencrypt.acme.jose import b64decode
        return b64decode(data)

    def test_unsafe_url(self):
        for text, b64 in B64_URL_UNSAFE_EXAMPLES.iteritems():
            self.assertEqual(self._call(b64), text)

    def test_input_without_padding(self):
        for text, (b64, _) in B64_PADDING_EXAMPLES.iteritems():
            self.assertEqual(self._call(b64), text)

    def test_input_with_padding(self):
        for text, (b64, pad) in B64_PADDING_EXAMPLES.iteritems():
            self.assertEqual(self._call(b64 + pad), text)

    def test_unicode_with_ascii(self):
        self.assertEqual(self._call(u'YQ'), 'a')

    def test_non_ascii_unicode_fails(self):
        self.assertRaises(ValueError, self._call, u'\u0105')

    def test_type_error_no_unicode_or_str(self):
        self.assertRaises(TypeError, self._call, object())


if __name__ == '__main__':
    unittest.main()
