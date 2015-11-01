"""Tests for acme.jose.jwk."""
import binascii
import unittest

from acme import test_util

from acme.jose import errors
from acme.jose import json_util
from acme.jose import util


DSA_PEM = test_util.load_vector('dsa512_key.pem')
RSA256_KEY = test_util.load_rsa_private_key('rsa256_key.pem')
RSA512_KEY = test_util.load_rsa_private_key('rsa512_key.pem')


class JWKTest(unittest.TestCase):
    """Tests for acme.jose.jwk.JWK."""

    def test_load(self):
        from acme.jose.jwk import JWK
        self.assertRaises(errors.Error, JWK.load, DSA_PEM)

    def test_load_subclass_wrong_type(self):
        from acme.jose.jwk import JWKRSA
        self.assertRaises(errors.Error, JWKRSA.load, DSA_PEM)


class JWKTestBaseMixin(object):
    """Mixin test for JWK subclass tests."""

    thumbprint = NotImplemented

    def test_thumbprint_private(self):
        self.assertEqual(self.thumbprint, self.jwk.thumbprint())

    def test_thumbprint_public(self):
        self.assertEqual(self.thumbprint, self.jwk.public_key().thumbprint())


class JWKOctTest(unittest.TestCase, JWKTestBaseMixin):
    """Tests for acme.jose.jwk.JWKOct."""

    thumbprint = (b"\xf3\xe7\xbe\xa8`\xd2\xdap\xe9}\x9c\xce>"
                  b"\xd0\xfcI\xbe\xcd\x92'\xd4o\x0e\xf41\xea"
                  b"\x8e(\x8a\xb2i\x1c")

    def setUp(self):
        from acme.jose.jwk import JWKOct
        self.jwk = JWKOct(key=b'foo')
        self.jobj = {'kty': 'oct', 'k': json_util.encode_b64jose(b'foo')}

    def test_to_partial_json(self):
        self.assertEqual(self.jwk.to_partial_json(), self.jobj)

    def test_from_json(self):
        from acme.jose.jwk import JWKOct
        self.assertEqual(self.jwk, JWKOct.from_json(self.jobj))

    def test_from_json_hashable(self):
        from acme.jose.jwk import JWKOct
        hash(JWKOct.from_json(self.jobj))

    def test_load(self):
        from acme.jose.jwk import JWKOct
        self.assertEqual(self.jwk, JWKOct.load(b'foo'))

    def test_public_key(self):
        self.assertTrue(self.jwk.public_key() is self.jwk)


class JWKRSATest(unittest.TestCase, JWKTestBaseMixin):
    """Tests for acme.jose.jwk.JWKRSA."""
    # pylint: disable=too-many-instance-attributes

    thumbprint = (b'\x83K\xdc#3\x98\xca\x98\xed\xcb\x80\x80<\x0c'
                  b'\xf0\x95\xb9H\xb2*l\xbd$\xe5&|O\x91\xd4 \xb0Y')

    def setUp(self):
        from acme.jose.jwk import JWKRSA
        self.jwk256 = JWKRSA(key=RSA256_KEY.public_key())
        self.jwk256json = {
            'kty': 'RSA',
            'e': 'AQAB',
            'n': 'm2Fylv-Uz7trgTW8EBHP3FQSMeZs2GNQ6VRo1sIVJEk',
        }
        # pylint: disable=protected-access
        self.jwk256_not_comparable = JWKRSA(
            key=RSA256_KEY.public_key()._wrapped)
        self.jwk512 = JWKRSA(key=RSA512_KEY.public_key())
        self.jwk512json = {
            'kty': 'RSA',
            'e': 'AQAB',
            'n': 'rHVztFHtH92ucFJD_N_HW9AsdRsUuHUBBBDlHwNlRd3fp5'
                 '80rv2-6QWE30cWgdmJS86ObRz6lUTor4R0T-3C5Q',
        }
        self.private = JWKRSA(key=RSA256_KEY)
        self.private_json_small = self.jwk256json.copy()
        self.private_json_small['d'] = (
            'lPQED_EPTV0UIBfNI3KP2d9Jlrc2mrMllmf946bu-CE')
        self.private_json = self.jwk256json.copy()
        self.private_json.update({
            'd': 'lPQED_EPTV0UIBfNI3KP2d9Jlrc2mrMllmf946bu-CE',
            'p': 'zUVNZn4lLLBD1R6NE8TKNQ',
            'q': 'wcfKfc7kl5jfqXArCRSURQ',
            'dp': 'CWJFq43QvT5Bm5iN8n1okQ',
            'dq': 'bHh2u7etM8LKKCF2pY2UdQ',
            'qi': 'oi45cEkbVoJjAbnQpFY87Q',
        })
        self.jwk = self.private

    def test_init_auto_comparable(self):
        self.assertTrue(isinstance(
            self.jwk256_not_comparable.key, util.ComparableRSAKey))
        self.assertEqual(self.jwk256, self.jwk256_not_comparable)

    def test_encode_param_zero(self):
        from acme.jose.jwk import JWKRSA
        # pylint: disable=protected-access
        # TODO: move encode/decode _param to separate class
        self.assertEqual('AA', JWKRSA._encode_param(0))

    def test_equals(self):
        self.assertEqual(self.jwk256, self.jwk256)
        self.assertEqual(self.jwk512, self.jwk512)

    def test_not_equals(self):
        self.assertNotEqual(self.jwk256, self.jwk512)
        self.assertNotEqual(self.jwk512, self.jwk256)

    def test_load(self):
        from acme.jose.jwk import JWKRSA
        self.assertEqual(self.private, JWKRSA.load(
            test_util.load_vector('rsa256_key.pem')))

    def test_public_key(self):
        self.assertEqual(self.jwk256, self.private.public_key())

    def test_to_partial_json(self):
        self.assertEqual(self.jwk256.to_partial_json(), self.jwk256json)
        self.assertEqual(self.jwk512.to_partial_json(), self.jwk512json)
        self.assertEqual(self.private.to_partial_json(), self.private_json)

    def test_from_json(self):
        from acme.jose.jwk import JWK
        self.assertEqual(
            self.jwk256, JWK.from_json(self.jwk256json))
        self.assertEqual(
            self.jwk512, JWK.from_json(self.jwk512json))
        self.assertEqual(self.private, JWK.from_json(self.private_json))

    def test_from_json_private_small(self):
        from acme.jose.jwk import JWK
        self.assertEqual(self.private, JWK.from_json(self.private_json_small))

    def test_from_json_missing_one_additional(self):
        from acme.jose.jwk import JWK
        del self.private_json['q']
        self.assertRaises(errors.Error, JWK.from_json, self.private_json)

    def test_from_json_hashable(self):
        from acme.jose.jwk import JWK
        hash(JWK.from_json(self.jwk256json))

    def test_from_json_non_schema_errors(self):
        # valid against schema, but still failing
        from acme.jose.jwk import JWK
        self.assertRaises(errors.DeserializationError, JWK.from_json,
                          {'kty': 'RSA', 'e': 'AQAB', 'n': ''})
        self.assertRaises(errors.DeserializationError, JWK.from_json,
                          {'kty': 'RSA', 'e': 'AQAB', 'n': '1'})

    def test_thumbprint_go_jose(self):
        # https://github.com/square/go-jose/blob/4ddd71883fa547d37fbf598071f04512d8bafee3/jwk.go#L155
        # https://github.com/square/go-jose/blob/4ddd71883fa547d37fbf598071f04512d8bafee3/jwk_test.go#L331-L344
        # https://github.com/square/go-jose/blob/4ddd71883fa547d37fbf598071f04512d8bafee3/jwk_test.go#L384
        from acme.jose.jwk import JWKRSA
        key = JWKRSA.json_loads("""{
    "kty": "RSA",
    "kid": "bilbo.baggins@hobbiton.example",
    "use": "sig",
    "n": "n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw",
    "e": "AQAB"
}""")
        self.assertEqual(
            binascii.hexlify(key.thumbprint()),
            b"f63838e96077ad1fc01c3f8405774dedc0641f558ebb4b40dccf5f9b6d66a932")


if __name__ == '__main__':
    unittest.main()  # pragma: no cover
