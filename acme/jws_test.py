"""Tests for acme.jws."""
import unittest

from acme import errors
from acme import jose
from acme import test_util


KEY = jose.JWKRSA.load(test_util.load_vector('rsa512_key.pem'))


class HeaderTest(unittest.TestCase):
    """Tests for acme.jws.Header."""

    good_nonce = jose.b64encode('foo')
    wrong_nonce = 'F'
    # Following just makes sure wrong_nonce is wrong
    try:
        jose.b64decode(wrong_nonce)
    except (ValueError, TypeError):
        assert True
    else:
        assert False  # pragma: no cover

    def test_validate_nonce(self):
        from acme.jws import Header
        self.assertTrue(Header.validate_nonce(self.good_nonce) is None)
        self.assertFalse(Header.validate_nonce(self.wrong_nonce) is None)

    def test_nonce_decoder(self):
        from acme.jws import Header
        nonce_field = Header._fields['nonce']

        self.assertRaises(errors.Error, nonce_field.decode, self.wrong_nonce)
        self.assertEqual(self.good_nonce, nonce_field.decode(self.good_nonce))


class JWSTest(unittest.TestCase):
    """Tests for acme.jws.JWS."""

    def setUp(self):
        self.privkey = KEY
        self.pubkey = self.privkey.public_key()
        self.nonce = jose.b64encode('Nonce')

    def test_it(self):
        from acme.jws import JWS
        jws = JWS.sign(payload='foo', key=self.privkey,
                       alg=jose.RS256, nonce=self.nonce)
        JWS.from_json(jws.to_json())


if __name__ == '__main__':
    unittest.main()  # pragma: no cover
