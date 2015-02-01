"""Tests for letsencrypt.acme.jose."""
import pkg_resources
import unittest

import Crypto.PublicKey.RSA


RSA256_KEY_PATH = pkg_resources.resource_string(
    'letsencrypt.client.tests', 'testdata/rsa256_key.pem')
RSA256_KEY = Crypto.PublicKey.RSA.importKey(RSA256_KEY_PATH)
RSA512_KEY_PATH = pkg_resources.resource_string(
    'letsencrypt.client.tests', 'testdata/rsa512_key.pem')
RSA512_KEY = Crypto.PublicKey.RSA.importKey(RSA512_KEY_PATH)


class JWKTest(unittest.TestCase):

    def setUp(self):
        from letsencrypt.acme.jose import JWK
        self.jwk256 = JWK(RSA256_KEY)
        self.jwk256json = {
            'kty': 'RSA',
            'e': 'AQAB',
            'n': 'rHVztFHtH92ucFJD_N_HW9AsdRsUuHUBBBDlHwNlRd3fp5'
                 '80rv2-6QWE30cWgdmJS86ObRz6lUTor4R0T-3C5Q',
        }
        self.jwk512 = JWK(RSA512_KEY)

    def test_equals(self):
        self.assertEqual(self.jwk256, self.jwk256)
        self.assertEqual(self.jwk512, self.jwk512)

    def test_not_equals(self):
        self.assertNotEqual(self.jwk256, self.jwk512)
        self.assertNotEqual(self.jwk512, self.jwk256)

    def test_equals_raises_type_error(self):
        self.assertRaises(TypeError, self.jwk256.__eq__, 123)

    def test_same_public_key(self):
        from letsencrypt.acme.jose import JWK
        self.assertTrue(self.jwk256.same_public_key(
            JWK(Crypto.PublicKey.RSA.importKey(RSA256_KEY_PATH))))

    def test_not_same_public_key(self):
        self.assertFalse(self.jwk256.same_public_key(self.jwk512))

    def test_same_public_key_raises_type_error(self):
        self.assertRaises(TypeError, self.jwk256.same_public_key, 5)

    def test_to_json(self):
        self.assertEqual(self.jwk256.to_json(), self.jwk256json)

    def test_from_json(self):
        from letsencrypt.acme.jose import JWK
        self.assertTrue(self.jwk256.same_public_key(
            JWK.from_json(self.jwk256json)))


if __name__ == "__main__":
    unittest.main()
