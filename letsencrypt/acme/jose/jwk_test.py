"""Tests for letsencrypt.acme.jose.jwk."""
import os
import pkg_resources
import unittest

from Crypto.PublicKey import RSA

from letsencrypt.acme.jose import errors


RSA256_KEY = RSA.importKey(pkg_resources.resource_string(
    'letsencrypt.client.tests', os.path.join('testdata', 'rsa256_key.pem')))
RSA512_KEY = RSA.importKey(pkg_resources.resource_string(
    'letsencrypt.client.tests', os.path.join('testdata', 'rsa512_key.pem')))


class JWKOctTest(unittest.TestCase):
    """Tests for letsencrypt.acme.jose.jwk.JWKOct."""

    def setUp(self):
        from letsencrypt.acme.jose.jwk import JWKOct
        self.jwk = JWKOct(key='foo')
        self.jobj = {'kty': 'oct', 'k': 'foo'}

    def test_to_json(self):
        self.assertEqual(self.jwk.to_json(), self.jobj)

    def test_from_json(self):
        from letsencrypt.acme.jose.jwk import JWKOct
        self.assertEqual(self.jwk, JWKOct.from_json(self.jobj))

    def test_load(self):
        from letsencrypt.acme.jose.jwk import JWKOct
        self.assertEqual(self.jwk, JWKOct.load('foo'))

    def test_public(self):
        self.assertTrue(self.jwk.public() is self.jwk)


class JWKRSATest(unittest.TestCase):
    """Tests for letsencrypt.acme.jose.jwk.JWKRSA."""

    def setUp(self):
        from letsencrypt.acme.jose.jwk import JWKRSA
        self.jwk256 = JWKRSA(key=RSA256_KEY.publickey())
        self.jwk256_private = JWKRSA(key=RSA256_KEY)
        self.jwk256json = {
            'kty': 'RSA',
            'e': 'AQAB',
            'n': 'rHVztFHtH92ucFJD_N_HW9AsdRsUuHUBBBDlHwNlRd3fp5'
                 '80rv2-6QWE30cWgdmJS86ObRz6lUTor4R0T-3C5Q',
        }
        self.jwk512 = JWKRSA(key=RSA512_KEY.publickey())
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

    def test_load(self):
        from letsencrypt.acme.jose.jwk import JWKRSA
        self.assertEqual(JWKRSA(key=RSA256_KEY), JWKRSA.load(
            pkg_resources.resource_string(
                'letsencrypt.client.tests',
                os.path.join('testdata', 'rsa256_key.pem'))))

    def test_public(self):
        self.assertEqual(self.jwk256, self.jwk256_private.public())

    def test_to_json(self):
        self.assertEqual(self.jwk256.to_json(), self.jwk256json)
        self.assertEqual(self.jwk512.to_json(), self.jwk512json)

    def test_from_json(self):
        from letsencrypt.acme.jose.jwk import JWK
        self.assertEqual(self.jwk256, JWK.from_json(self.jwk256json))
        # TODO: fix schemata to allow RSA512
        #self.assertEqual(self.jwk512, JWK.from_json(self.jwk512json))

    def test_from_json_non_schema_errors(self):
        # valid against schema, but still failing
        from letsencrypt.acme.jose.jwk import JWK
        self.assertRaises(errors.DeserializationError, JWK.from_json,
                          {'kty': 'RSA', 'e': 'AQAB', 'n': ''})
        self.assertRaises(errors.DeserializationError, JWK.from_json,
                          {'kty': 'RSA', 'e': 'AQAB', 'n': '1'})


if __name__ == '__main__':
    unittest.main()
