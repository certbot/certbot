"""Tests for acme.jws."""
import unittest

import josepy as jose

from acme.mixins import ResourceMixin

import test_util

KEY = jose.JWKRSA.load(test_util.load_vector('rsa512_key.pem'))


class HeaderTest(unittest.TestCase):
    """Tests for acme.jws.Header."""

    good_nonce = jose.encode_b64jose(b'foo')
    wrong_nonce = u'F'
    # Following just makes sure wrong_nonce is wrong
    try:
        jose.b64decode(wrong_nonce)
    except (ValueError, TypeError):
        assert True
    else:
        assert False  # pragma: no cover

    def test_nonce_decoder(self):
        from acme.jws import Header
        nonce_field = Header._fields['nonce']

        self.assertRaises(
            jose.DeserializationError, nonce_field.decode, self.wrong_nonce)
        self.assertEqual(b'foo', nonce_field.decode(self.good_nonce))


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
        self.assertEqual(jws.signature.combined.nonce, self.nonce)
        self.assertEqual(jws.signature.combined.url, self.url)
        self.assertEqual(jws.signature.combined.kid, self.kid)
        self.assertEqual(jws.signature.combined.jwk, None)
        # TODO: check that nonce is in protected header

        self.assertEqual(jws, JWS.from_json(jws.to_json()))

    def test_jwk_serialize(self):
        from acme.jws import JWS
        jws = JWS.sign(payload=b'foo', key=self.privkey,
                       alg=jose.RS256, nonce=self.nonce,
                       url=self.url)
        self.assertEqual(jws.signature.combined.kid, None)
        self.assertEqual(jws.signature.combined.jwk, self.pubkey)


class JWSPayloadRFC8555Compliant(unittest.TestCase):
    """Test for RFC8555 compliance of JWS generated from resources/challenges"""
    def test_challenge_payload(self):
        from acme.challenges import HTTP01Response

        challenge_body = HTTP01Response()
        challenge_body.le_auto_version = 2

        jobj = challenge_body.json_dumps(indent=2).encode()
        # RFC8555 states that challenge requests must have an empty payload.
        self.assertEqual(jobj, b'{}')

    def test_resource_payload(self):
        from acme.messages import ResourceBody
        from acme import fields

        class _MockResourceResponse(ResourceMixin, ResourceBody):
            resource_type = 'one-resource'
            resource = fields.Resource(resource_type)

        resource_body = _MockResourceResponse()
        resource_body.le_auto_version = 2

        jobj = resource_body.json_dumps(indent=2).encode()
        # Having a resource field in JWS payloads for resources is not compliant with RFC8555.
        self.assertTrue(b'resource' not in jobj)


if __name__ == '__main__':
    unittest.main()  # pragma: no cover
