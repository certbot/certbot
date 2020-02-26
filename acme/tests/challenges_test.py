"""Tests for acme.challenges."""
import unittest

import josepy as jose
import mock
import requests
from six.moves.urllib import parse as urllib_parse

import test_util

CERT = test_util.load_comparable_cert('cert.pem')
KEY = jose.JWKRSA(key=test_util.load_rsa_private_key('rsa512_key.pem'))


class ChallengeTest(unittest.TestCase):

    def test_from_json_unrecognized(self):
        from acme.challenges import Challenge
        from acme.challenges import UnrecognizedChallenge
        chall = UnrecognizedChallenge({"type": "foo"})
        self.assertEqual(chall, Challenge.from_json(chall.jobj))


class UnrecognizedChallengeTest(unittest.TestCase):

    def setUp(self):
        from acme.challenges import UnrecognizedChallenge
        self.jobj = {"type": "foo"}
        self.chall = UnrecognizedChallenge(self.jobj)

    def test_to_partial_json(self):
        self.assertEqual(self.jobj, self.chall.to_partial_json())

    def test_from_json(self):
        from acme.challenges import UnrecognizedChallenge
        self.assertEqual(
            self.chall, UnrecognizedChallenge.from_json(self.jobj))


class KeyAuthorizationChallengeResponseTest(unittest.TestCase):

    def setUp(self):
        def _encode(name):
            assert name == "token"
            return "foo"
        self.chall = mock.Mock()
        self.chall.encode.side_effect = _encode

    def test_verify_ok(self):
        from acme.challenges import KeyAuthorizationChallengeResponse
        response = KeyAuthorizationChallengeResponse(
            key_authorization='foo.oKGqedy-b-acd5eoybm2f-NVFxvyOoET5CNy3xnv8WY')
        self.assertTrue(response.verify(self.chall, KEY.public_key()))

    def test_verify_wrong_token(self):
        from acme.challenges import KeyAuthorizationChallengeResponse
        response = KeyAuthorizationChallengeResponse(
            key_authorization='bar.oKGqedy-b-acd5eoybm2f-NVFxvyOoET5CNy3xnv8WY')
        self.assertFalse(response.verify(self.chall, KEY.public_key()))

    def test_verify_wrong_thumbprint(self):
        from acme.challenges import KeyAuthorizationChallengeResponse
        response = KeyAuthorizationChallengeResponse(
            key_authorization='foo.oKGqedy-b-acd5eoybm2f-NVFxv')
        self.assertFalse(response.verify(self.chall, KEY.public_key()))

    def test_verify_wrong_form(self):
        from acme.challenges import KeyAuthorizationChallengeResponse
        response = KeyAuthorizationChallengeResponse(
            key_authorization='.foo.oKGqedy-b-acd5eoybm2f-'
            'NVFxvyOoET5CNy3xnv8WY')
        self.assertFalse(response.verify(self.chall, KEY.public_key()))


class DNS01ResponseTest(unittest.TestCase):

    def setUp(self):
        from acme.challenges import DNS01Response
        self.msg = DNS01Response(key_authorization=u'foo')
        self.jmsg = {
            'resource': 'challenge',
            'type': 'dns-01',
            'keyAuthorization': u'foo',
        }

        from acme.challenges import DNS01
        self.chall = DNS01(token=(b'x' * 16))
        self.response = self.chall.response(KEY)

    def test_to_partial_json(self):
        self.assertEqual({k: v for k, v in self.jmsg.items() if k != 'keyAuthorization'},
                         self.msg.to_partial_json())

    def test_from_json(self):
        from acme.challenges import DNS01Response
        self.assertEqual(self.msg, DNS01Response.from_json(self.jmsg))

    def test_from_json_hashable(self):
        from acme.challenges import DNS01Response
        hash(DNS01Response.from_json(self.jmsg))

    def test_simple_verify_failure(self):
        key2 = jose.JWKRSA.load(test_util.load_vector('rsa256_key.pem'))
        public_key = key2.public_key()
        verified = self.response.simple_verify(self.chall, "local", public_key)
        self.assertFalse(verified)

    def test_simple_verify_success(self):
        public_key = KEY.public_key()
        verified = self.response.simple_verify(self.chall, "local", public_key)
        self.assertTrue(verified)


class DNS01Test(unittest.TestCase):

    def setUp(self):
        from acme.challenges import DNS01
        self.msg = DNS01(token=jose.decode_b64jose(
            'evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ+PCt92wr+oA'))
        self.jmsg = {
            'type': 'dns-01',
            'token': 'evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA',
        }

    def test_validation_domain_name(self):
        self.assertEqual('_acme-challenge.www.example.com',
                         self.msg.validation_domain_name('www.example.com'))

    def test_validation(self):
        self.assertEqual(
            "rAa7iIg4K2y63fvUhCfy8dP1Xl7wEhmQq0oChTcE3Zk",
            self.msg.validation(KEY))

    def test_to_partial_json(self):
        self.assertEqual(self.jmsg, self.msg.to_partial_json())

    def test_from_json(self):
        from acme.challenges import DNS01
        self.assertEqual(self.msg, DNS01.from_json(self.jmsg))

    def test_from_json_hashable(self):
        from acme.challenges import DNS01
        hash(DNS01.from_json(self.jmsg))


class HTTP01ResponseTest(unittest.TestCase):

    def setUp(self):
        from acme.challenges import HTTP01Response
        self.msg = HTTP01Response(key_authorization=u'foo')
        self.jmsg = {
            'resource': 'challenge',
            'type': 'http-01',
            'keyAuthorization': u'foo',
        }

        from acme.challenges import HTTP01
        self.chall = HTTP01(token=(b'x' * 16))
        self.response = self.chall.response(KEY)

    def test_to_partial_json(self):
        self.assertEqual({k: v for k, v in self.jmsg.items() if k != 'keyAuthorization'},
                         self.msg.to_partial_json())

    def test_from_json(self):
        from acme.challenges import HTTP01Response
        self.assertEqual(
            self.msg, HTTP01Response.from_json(self.jmsg))

    def test_from_json_hashable(self):
        from acme.challenges import HTTP01Response
        hash(HTTP01Response.from_json(self.jmsg))

    def test_simple_verify_bad_key_authorization(self):
        key2 = jose.JWKRSA.load(test_util.load_vector('rsa256_key.pem'))
        self.response.simple_verify(self.chall, "local", key2.public_key())

    @mock.patch("acme.challenges.requests.get")
    def test_simple_verify_good_validation(self, mock_get):
        validation = self.chall.validation(KEY)
        mock_get.return_value = mock.MagicMock(text=validation)
        self.assertTrue(self.response.simple_verify(
            self.chall, "local", KEY.public_key()))
        mock_get.assert_called_once_with(self.chall.uri("local"), verify=False)

    @mock.patch("acme.challenges.requests.get")
    def test_simple_verify_bad_validation(self, mock_get):
        mock_get.return_value = mock.MagicMock(text="!")
        self.assertFalse(self.response.simple_verify(
            self.chall, "local", KEY.public_key()))

    @mock.patch("acme.challenges.requests.get")
    def test_simple_verify_whitespace_validation(self, mock_get):
        from acme.challenges import HTTP01Response
        mock_get.return_value = mock.MagicMock(
            text=(self.chall.validation(KEY) +
                  HTTP01Response.WHITESPACE_CUTSET))
        self.assertTrue(self.response.simple_verify(
            self.chall, "local", KEY.public_key()))
        mock_get.assert_called_once_with(self.chall.uri("local"), verify=False)

    @mock.patch("acme.challenges.requests.get")
    def test_simple_verify_connection_error(self, mock_get):
        mock_get.side_effect = requests.exceptions.RequestException
        self.assertFalse(self.response.simple_verify(
            self.chall, "local", KEY.public_key()))

    @mock.patch("acme.challenges.requests.get")
    def test_simple_verify_port(self, mock_get):
        self.response.simple_verify(
            self.chall, domain="local",
            account_public_key=KEY.public_key(), port=8080)
        self.assertEqual("local:8080", urllib_parse.urlparse(
            mock_get.mock_calls[0][1][0]).netloc)


class HTTP01Test(unittest.TestCase):

    def setUp(self):
        from acme.challenges import HTTP01
        self.msg = HTTP01(
            token=jose.decode_b64jose(
                'evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ+PCt92wr+oA'))
        self.jmsg = {
            'type': 'http-01',
            'token': 'evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA',
        }

    def test_path(self):
        self.assertEqual(self.msg.path, '/.well-known/acme-challenge/'
                         'evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA')

    def test_uri(self):
        self.assertEqual(
            'http://example.com/.well-known/acme-challenge/'
            'evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA',
            self.msg.uri('example.com'))

    def test_to_partial_json(self):
        self.assertEqual(self.jmsg, self.msg.to_partial_json())

    def test_from_json(self):
        from acme.challenges import HTTP01
        self.assertEqual(self.msg, HTTP01.from_json(self.jmsg))

    def test_from_json_hashable(self):
        from acme.challenges import HTTP01
        hash(HTTP01.from_json(self.jmsg))

    def test_good_token(self):
        self.assertTrue(self.msg.good_token)
        self.assertFalse(
            self.msg.update(token=b'..').good_token)


class TLSALPN01ResponseTest(unittest.TestCase):

    def setUp(self):
        from acme.challenges import TLSALPN01Response
        self.msg = TLSALPN01Response(key_authorization=u'foo')
        self.jmsg = {
            'resource': 'challenge',
            'type': 'tls-alpn-01',
            'keyAuthorization': u'foo',
        }

        from acme.challenges import TLSALPN01
        self.chall = TLSALPN01(token=(b'x' * 16))
        self.response = self.chall.response(KEY)

    def test_to_partial_json(self):
        self.assertEqual({k: v for k, v in self.jmsg.items() if k != 'keyAuthorization'},
                         self.msg.to_partial_json())

    def test_from_json(self):
        from acme.challenges import TLSALPN01Response
        self.assertEqual(self.msg, TLSALPN01Response.from_json(self.jmsg))

    def test_from_json_hashable(self):
        from acme.challenges import TLSALPN01Response
        hash(TLSALPN01Response.from_json(self.jmsg))


class TLSALPN01Test(unittest.TestCase):

    def setUp(self):
        from acme.challenges import TLSALPN01
        self.msg = TLSALPN01(
            token=jose.b64decode('a82d5ff8ef740d12881f6d3c2277ab2e'))
        self.jmsg = {
            'type': 'tls-alpn-01',
            'token': 'a82d5ff8ef740d12881f6d3c2277ab2e',
        }

    def test_to_partial_json(self):
        self.assertEqual(self.jmsg, self.msg.to_partial_json())

    def test_from_json(self):
        from acme.challenges import TLSALPN01
        self.assertEqual(self.msg, TLSALPN01.from_json(self.jmsg))

    def test_from_json_hashable(self):
        from acme.challenges import TLSALPN01
        hash(TLSALPN01.from_json(self.jmsg))

    def test_from_json_invalid_token_length(self):
        from acme.challenges import TLSALPN01
        self.jmsg['token'] = jose.encode_b64jose(b'abcd')
        self.assertRaises(
            jose.DeserializationError, TLSALPN01.from_json, self.jmsg)

    def test_validation(self):
        self.assertRaises(NotImplementedError, self.msg.validation, KEY)


class DNSTest(unittest.TestCase):

    def setUp(self):
        from acme.challenges import DNS
        self.msg = DNS(token=jose.b64decode(
            b'evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA'))
        self.jmsg = {
            'type': 'dns',
            'token': 'evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA',
        }

    def test_to_partial_json(self):
        self.assertEqual(self.jmsg, self.msg.to_partial_json())

    def test_from_json(self):
        from acme.challenges import DNS
        self.assertEqual(self.msg, DNS.from_json(self.jmsg))

    def test_from_json_hashable(self):
        from acme.challenges import DNS
        hash(DNS.from_json(self.jmsg))

    def test_gen_check_validation(self):
        self.assertTrue(self.msg.check_validation(
            self.msg.gen_validation(KEY), KEY.public_key()))

    def test_gen_check_validation_wrong_key(self):
        key2 = jose.JWKRSA.load(test_util.load_vector('rsa1024_key.pem'))
        self.assertFalse(self.msg.check_validation(
            self.msg.gen_validation(KEY), key2.public_key()))

    def test_check_validation_wrong_payload(self):
        validations = tuple(
            jose.JWS.sign(payload=payload, alg=jose.RS256, key=KEY)
            for payload in (b'', b'{}')
        )
        for validation in validations:
            self.assertFalse(self.msg.check_validation(
                validation, KEY.public_key()))

    def test_check_validation_wrong_fields(self):
        bad_validation = jose.JWS.sign(
            payload=self.msg.update(
                token=b'x' * 20).json_dumps().encode('utf-8'),
            alg=jose.RS256, key=KEY)
        self.assertFalse(self.msg.check_validation(
            bad_validation, KEY.public_key()))

    def test_gen_response(self):
        with mock.patch('acme.challenges.DNS.gen_validation') as mock_gen:
            mock_gen.return_value = mock.sentinel.validation
            response = self.msg.gen_response(KEY)
        from acme.challenges import DNSResponse
        self.assertTrue(isinstance(response, DNSResponse))
        self.assertEqual(response.validation, mock.sentinel.validation)

    def test_validation_domain_name(self):
        self.assertEqual(
            '_acme-challenge.le.wtf', self.msg.validation_domain_name('le.wtf'))


class DNSResponseTest(unittest.TestCase):

    def setUp(self):
        from acme.challenges import DNS
        self.chall = DNS(token=jose.b64decode(
            b"evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA"))
        self.validation = jose.JWS.sign(
            payload=self.chall.json_dumps(sort_keys=True).encode(),
            key=KEY, alg=jose.RS256)

        from acme.challenges import DNSResponse
        self.msg = DNSResponse(validation=self.validation)
        self.jmsg_to = {
            'resource': 'challenge',
            'type': 'dns',
            'validation': self.validation,
        }
        self.jmsg_from = {
            'resource': 'challenge',
            'type': 'dns',
            'validation': self.validation.to_json(),
        }

    def test_to_partial_json(self):
        self.assertEqual(self.jmsg_to, self.msg.to_partial_json())

    def test_from_json(self):
        from acme.challenges import DNSResponse
        self.assertEqual(self.msg, DNSResponse.from_json(self.jmsg_from))

    def test_from_json_hashable(self):
        from acme.challenges import DNSResponse
        hash(DNSResponse.from_json(self.jmsg_from))

    def test_check_validation(self):
        self.assertTrue(
            self.msg.check_validation(self.chall, KEY.public_key()))


if __name__ == '__main__':
    unittest.main()  # pragma: no cover
