"""Tests for acme.sig."""
import unittest

from acme import jose
from acme import test_util


KEY = test_util.load_rsa_private_key('rsa512_key.pem')


class SignatureTest(unittest.TestCase):
    # pylint: disable=too-many-instance-attributes
    """Tests for acme.sig.Signature."""

    def setUp(self):
        self.msg = b'message'
        self.sig = (b'IC\xd8*\xe7\x14\x9e\x19S\xb7\xcf\xec3\x12\xe2\x8a\x03'
                    b'\x98u\xff\xf0\x94\xe2\xd7<\x8f\xa8\xed\xa4KN\xc3\xaa'
                    b'\xb9X\xc3w\xaa\xc0_\xd0\x05$y>l#\x10<\x96\xd2\xcdr\xa3'
                    b'\x1b\xa1\xf5!f\xef\xc64\xb6\x13')
        self.nonce = b'\xec\xd6\xf2oYH\xeb\x13\xd5#q\xe0\xdd\xa2\x92\xa9'

        self.alg = jose.RS256
        self.jwk = jose.JWKRSA(key=KEY.public_key())

        b64sig = ('SUPYKucUnhlTt8_sMxLiigOYdf_wlOLXPI-o7aRLTsOquVjDd6r'
                  'AX9AFJHk-bCMQPJbSzXKjG6H1IWbvxjS2Ew')
        b64nonce = '7Nbyb1lI6xPVI3Hg3aKSqQ'
        self.jsig_to = {
            'nonce': b64nonce,
            'alg': self.alg,
            'jwk': self.jwk,
            'sig': b64sig,
        }

        self.jsig_from = {
            'nonce': b64nonce,
            'alg': self.alg.to_partial_json(),
            'jwk': self.jwk.to_partial_json(),
            'sig': b64sig,
        }

        from acme.other import Signature
        self.signature = Signature(
            alg=self.alg, sig=self.sig, nonce=self.nonce, jwk=self.jwk)

    def test_attributes(self):
        self.assertEqual(self.signature.nonce, self.nonce)
        self.assertEqual(self.signature.alg, self.alg)
        self.assertEqual(self.signature.sig, self.sig)
        self.assertEqual(self.signature.jwk, self.jwk)

    def test_verify_good_succeeds(self):
        self.assertTrue(self.signature.verify(self.msg))

    def test_verify_bad_fails(self):
        self.assertFalse(self.signature.verify(self.msg + b'x'))

    @classmethod
    def _from_msg(cls, *args, **kwargs):
        from acme.other import Signature
        return Signature.from_msg(*args, **kwargs)

    def test_create_from_msg(self):
        signature = self._from_msg(self.msg, KEY, self.nonce)
        self.assertEqual(self.signature, signature)

    def test_create_from_msg_random_nonce(self):
        signature = self._from_msg(self.msg, KEY)
        self.assertEqual(signature.alg, self.alg)
        self.assertEqual(signature.jwk, self.jwk)
        self.assertTrue(signature.verify(self.msg))

    def test_to_partial_json(self):
        self.assertEqual(self.signature.to_partial_json(), self.jsig_to)

    def test_from_json(self):
        from acme.other import Signature
        self.assertEqual(
            self.signature, Signature.from_json(self.jsig_from))

    def test_from_json_non_schema_errors(self):
        from acme.other import Signature
        jwk = self.jwk.to_partial_json()
        self.assertRaises(
            jose.DeserializationError, Signature.from_json, {
                'alg': 'RS256', 'sig': 'x', 'nonce': '', 'jwk': jwk})
        self.assertRaises(
            jose.DeserializationError, Signature.from_json, {
                'alg': 'RS256', 'sig': '', 'nonce': 'x', 'jwk': jwk})


if __name__ == '__main__':
    unittest.main()  # pragma: no cover
