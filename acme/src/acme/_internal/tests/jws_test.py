"""Tests for acme.jws."""
import sys
import unittest

import josepy as jose
import pytest

from acme._internal.tests import test_util

KEY = jose.JWKRSA.load(test_util.load_vector('rsa512_key.pem'))


class HeaderTest(unittest.TestCase):
    """Tests for acme.jws.Header."""

    good_nonce = jose.encode_b64jose(b'foo')
    wrong_nonce = 'F'
    # Following just makes sure wrong_nonce is wrong
    try:
        jose.b64decode(wrong_nonce)
    except (ValueError, TypeError):
        assert True
    else:
        pytest.fail("Exception from jose.b64decode wasn't raised")  # pragma: no cover

    def test_nonce_decoder(self):
        from acme.jws import Header
        nonce_field = Header._fields['nonce']

        with pytest.raises(jose.DeserializationError):
            nonce_field.decode(self.wrong_nonce)
        assert b'foo' == nonce_field.decode(self.good_nonce)


class JWSTest(unittest.TestCase):
    """Tests for acme.jws.JWS."""

    def setUp(self):
        self.privkey = KEY
        self.pubkey = self.privkey.public_key()
        self.nonce = jose.b64encode(b'Nonce')
        self.url = 'hi'
        self.kid = 'baaaaa'

    def test_kid_serialize(self):
        from acme.jws import JWS
        jws = JWS.sign(payload=b'foo', key=self.privkey,
                       alg=jose.RS256, nonce=self.nonce,
                       url=self.url, kid=self.kid)
        assert jws.signature.combined.nonce == self.nonce
        assert jws.signature.combined.url == self.url
        assert jws.signature.combined.kid == self.kid
        assert jws.signature.combined.jwk is None
        # TODO: check that nonce is in protected header

        assert jws == JWS.from_json(jws.to_json())

    def test_jwk_serialize(self):
        from acme.jws import JWS
        jws = JWS.sign(payload=b'foo', key=self.privkey,
                       alg=jose.RS256, nonce=self.nonce,
                       url=self.url)
        assert jws.signature.combined.kid is None
        assert jws.signature.combined.jwk == self.pubkey


if __name__ == '__main__':
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover
