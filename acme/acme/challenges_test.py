"""Tests for acme.challenges."""
import unittest

import mock
import OpenSSL
import requests

from six.moves.urllib import parse as urllib_parse  # pylint: disable=import-error

from acme import errors
from acme import jose
from acme import other
from acme import test_util


CERT = test_util.load_cert('cert.pem')
KEY = jose.JWKRSA(key=test_util.load_rsa_private_key('rsa512_key.pem'))


class ChallengeTest(unittest.TestCase):

    def test_from_json_unrecognized(self):
        from acme.challenges import Challenge
        from acme.challenges import UnrecognizedChallenge
        chall = UnrecognizedChallenge({"type": "foo"})
        # pylint: disable=no-member
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
            key_authorization='.foo.oKGqedy-b-acd5eoybm2f-NVFxvyOoET5CNy3xnv8WY')
        self.assertFalse(response.verify(self.chall, KEY.public_key()))


class HTTP01ResponseTest(unittest.TestCase):
    # pylint: disable=too-many-instance-attributes

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
        self.assertEqual(self.jmsg, self.msg.to_partial_json())

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
        mock_get.assert_called_once_with(self.chall.uri("local"))

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
        mock_get.assert_called_once_with(self.chall.uri("local"))

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


class TLSSNI01ResponseTest(unittest.TestCase):
    # pylint: disable=too-many-instance-attributes

    def setUp(self):
        from acme.challenges import TLSSNI01
        self.chall = TLSSNI01(
            token=jose.b64decode(b'a82d5ff8ef740d12881f6d3c2277ab2e'))

        self.response = self.chall.response(KEY)
        self.jmsg = {
            'resource': 'challenge',
            'type': 'tls-sni-01',
            'keyAuthorization': self.response.key_authorization,
        }

        # pylint: disable=invalid-name
        label1 = b'dc38d9c3fa1a4fdcc3a5501f2d38583f'
        label2 = b'b7793728f084394f2a1afd459556bb5c'
        self.z = label1 + label2
        self.z_domain = label1 + b'.' + label2 + b'.acme.invalid'
        self.domain = 'foo.com'

    def test_z_and_domain(self):
        self.assertEqual(self.z, self.response.z)
        self.assertEqual(self.z_domain, self.response.z_domain)

    def test_to_partial_json(self):
        self.assertEqual(self.jmsg, self.response.to_partial_json())

    def test_from_json(self):
        from acme.challenges import TLSSNI01Response
        self.assertEqual(self.response, TLSSNI01Response.from_json(self.jmsg))

    def test_from_json_hashable(self):
        from acme.challenges import TLSSNI01Response
        hash(TLSSNI01Response.from_json(self.jmsg))

    @mock.patch('acme.challenges.socket.gethostbyname')
    @mock.patch('acme.challenges.crypto_util.probe_sni')
    def test_probe_cert(self, mock_probe_sni, mock_gethostbyname):
        mock_gethostbyname.return_value = '127.0.0.1'
        self.response.probe_cert('foo.com')
        mock_gethostbyname.assert_called_once_with('foo.com')
        mock_probe_sni.assert_called_once_with(
            host='127.0.0.1', port=self.response.PORT,
            name=self.z_domain)

        self.response.probe_cert('foo.com', host='8.8.8.8')
        mock_probe_sni.assert_called_with(
            host='8.8.8.8', port=mock.ANY, name=mock.ANY)

        self.response.probe_cert('foo.com', port=1234)
        mock_probe_sni.assert_called_with(
            host=mock.ANY, port=1234, name=mock.ANY)

        self.response.probe_cert('foo.com', bar='baz')
        mock_probe_sni.assert_called_with(
            host=mock.ANY, port=mock.ANY, name=mock.ANY, bar='baz')

        self.response.probe_cert('foo.com', name=b'xxx')
        mock_probe_sni.assert_called_with(
            host=mock.ANY, port=mock.ANY,
            name=self.z_domain)

    def test_gen_verify_cert(self):
        key1 = test_util.load_pyopenssl_private_key('rsa512_key.pem')
        cert, key2 = self.response.gen_cert(key1)
        self.assertEqual(key1, key2)
        self.assertTrue(self.response.verify_cert(cert))

    def test_gen_verify_cert_gen_key(self):
        cert, key = self.response.gen_cert()
        self.assertTrue(isinstance(key, OpenSSL.crypto.PKey))
        self.assertTrue(self.response.verify_cert(cert))

    def test_verify_bad_cert(self):
        self.assertFalse(self.response.verify_cert(
            test_util.load_cert('cert.pem')))

    def test_simple_verify_bad_key_authorization(self):
        key2 = jose.JWKRSA.load(test_util.load_vector('rsa256_key.pem'))
        self.response.simple_verify(self.chall, "local", key2.public_key())

    @mock.patch('acme.challenges.TLSSNI01Response.verify_cert', autospec=True)
    def test_simple_verify(self, mock_verify_cert):
        mock_verify_cert.return_value = mock.sentinel.verification
        self.assertEqual(mock.sentinel.verification, self.response.simple_verify(
            self.chall, self.domain, KEY.public_key(),
            cert=mock.sentinel.cert))
        mock_verify_cert.assert_called_once_with(self.response, mock.sentinel.cert)

    @mock.patch('acme.challenges.TLSSNI01Response.probe_cert')
    def test_simple_verify_false_on_probe_error(self, mock_probe_cert):
        mock_probe_cert.side_effect = errors.Error
        self.assertFalse(self.response.simple_verify(
            self.chall, self.domain, KEY.public_key()))


class TLSSNI01Test(unittest.TestCase):

    def setUp(self):
        from acme.challenges import TLSSNI01
        self.msg = TLSSNI01(
            token=jose.b64decode('a82d5ff8ef740d12881f6d3c2277ab2e'))
        self.jmsg = {
            'type': 'tls-sni-01',
            'token': 'a82d5ff8ef740d12881f6d3c2277ab2e',
        }

    def test_to_partial_json(self):
        self.assertEqual(self.jmsg, self.msg.to_partial_json())

    def test_from_json(self):
        from acme.challenges import TLSSNI01
        self.assertEqual(self.msg, TLSSNI01.from_json(self.jmsg))

    def test_from_json_hashable(self):
        from acme.challenges import TLSSNI01
        hash(TLSSNI01.from_json(self.jmsg))

    def test_from_json_invalid_token_length(self):
        from acme.challenges import TLSSNI01
        self.jmsg['token'] = jose.encode_b64jose(b'abcd')
        self.assertRaises(
            jose.DeserializationError, TLSSNI01.from_json, self.jmsg)

    @mock.patch('acme.challenges.TLSSNI01Response.gen_cert')
    def test_validation(self, mock_gen_cert):
        mock_gen_cert.return_value = ('cert', 'key')
        self.assertEqual(('cert', 'key'), self.msg.validation(
            KEY, cert_key=mock.sentinel.cert_key))
        mock_gen_cert.assert_called_once_with(key=mock.sentinel.cert_key)


class RecoveryContactTest(unittest.TestCase):

    def setUp(self):
        from acme.challenges import RecoveryContact
        self.msg = RecoveryContact(
            activation_url='https://example.ca/sendrecovery/a5bd99383fb0',
            success_url='https://example.ca/confirmrecovery/bb1b9928932',
            contact='c********n@example.com')
        self.jmsg = {
            'type': 'recoveryContact',
            'activationURL': 'https://example.ca/sendrecovery/a5bd99383fb0',
            'successURL': 'https://example.ca/confirmrecovery/bb1b9928932',
            'contact': 'c********n@example.com',
        }

    def test_to_partial_json(self):
        self.assertEqual(self.jmsg, self.msg.to_partial_json())

    def test_from_json(self):
        from acme.challenges import RecoveryContact
        self.assertEqual(self.msg, RecoveryContact.from_json(self.jmsg))

    def test_from_json_hashable(self):
        from acme.challenges import RecoveryContact
        hash(RecoveryContact.from_json(self.jmsg))

    def test_json_without_optionals(self):
        del self.jmsg['activationURL']
        del self.jmsg['successURL']
        del self.jmsg['contact']

        from acme.challenges import RecoveryContact
        msg = RecoveryContact.from_json(self.jmsg)

        self.assertTrue(msg.activation_url is None)
        self.assertTrue(msg.success_url is None)
        self.assertTrue(msg.contact is None)
        self.assertEqual(self.jmsg, msg.to_partial_json())


class RecoveryContactResponseTest(unittest.TestCase):

    def setUp(self):
        from acme.challenges import RecoveryContactResponse
        self.msg = RecoveryContactResponse(token='23029d88d9e123e')
        self.jmsg = {
            'resource': 'challenge',
            'type': 'recoveryContact',
            'token': '23029d88d9e123e',
        }

    def test_to_partial_json(self):
        self.assertEqual(self.jmsg, self.msg.to_partial_json())

    def test_from_json(self):
        from acme.challenges import RecoveryContactResponse
        self.assertEqual(
            self.msg, RecoveryContactResponse.from_json(self.jmsg))

    def test_from_json_hashable(self):
        from acme.challenges import RecoveryContactResponse
        hash(RecoveryContactResponse.from_json(self.jmsg))

    def test_json_without_optionals(self):
        del self.jmsg['token']

        from acme.challenges import RecoveryContactResponse
        msg = RecoveryContactResponse.from_json(self.jmsg)

        self.assertTrue(msg.token is None)
        self.assertEqual(self.jmsg, msg.to_partial_json())


class ProofOfPossessionHintsTest(unittest.TestCase):

    def setUp(self):
        jwk = KEY.public_key()
        issuers = (
            'C=US, O=SuperT LLC, CN=SuperTrustworthy Public CA',
            'O=LessTrustworthy CA Inc, CN=LessTrustworthy But StillSecure',
        )
        cert_fingerprints = (
            '93416768eb85e33adc4277f4c9acd63e7418fcfe',
            '16d95b7b63f1972b980b14c20291f3c0d1855d95',
            '48b46570d9fc6358108af43ad1649484def0debf',
        )
        subject_key_identifiers = ('d0083162dcc4c8a23ecb8aecbd86120e56fd24e5')
        authorized_for = ('www.example.com', 'example.net')
        serial_numbers = (34234239832, 23993939911, 17)

        from acme.challenges import ProofOfPossession
        self.msg = ProofOfPossession.Hints(
            jwk=jwk, issuers=issuers, cert_fingerprints=cert_fingerprints,
            certs=(CERT,), subject_key_identifiers=subject_key_identifiers,
            authorized_for=authorized_for, serial_numbers=serial_numbers)

        self.jmsg_to = {
            'jwk': jwk,
            'certFingerprints': cert_fingerprints,
            'certs': (jose.encode_b64jose(OpenSSL.crypto.dump_certificate(
                OpenSSL.crypto.FILETYPE_ASN1, CERT)),),
            'subjectKeyIdentifiers': subject_key_identifiers,
            'serialNumbers': serial_numbers,
            'issuers': issuers,
            'authorizedFor': authorized_for,
        }
        self.jmsg_from = self.jmsg_to.copy()
        self.jmsg_from.update({'jwk': jwk.to_json()})

    def test_to_partial_json(self):
        self.assertEqual(self.jmsg_to, self.msg.to_partial_json())

    def test_from_json(self):
        from acme.challenges import ProofOfPossession
        self.assertEqual(
            self.msg, ProofOfPossession.Hints.from_json(self.jmsg_from))

    def test_from_json_hashable(self):
        from acme.challenges import ProofOfPossession
        hash(ProofOfPossession.Hints.from_json(self.jmsg_from))

    def test_json_without_optionals(self):
        for optional in ['certFingerprints', 'certs', 'subjectKeyIdentifiers',
                         'serialNumbers', 'issuers', 'authorizedFor']:
            del self.jmsg_from[optional]
            del self.jmsg_to[optional]

        from acme.challenges import ProofOfPossession
        msg = ProofOfPossession.Hints.from_json(self.jmsg_from)

        self.assertEqual(msg.cert_fingerprints, ())
        self.assertEqual(msg.certs, ())
        self.assertEqual(msg.subject_key_identifiers, ())
        self.assertEqual(msg.serial_numbers, ())
        self.assertEqual(msg.issuers, ())
        self.assertEqual(msg.authorized_for, ())

        self.assertEqual(self.jmsg_to, msg.to_partial_json())


class ProofOfPossessionTest(unittest.TestCase):

    def setUp(self):
        from acme.challenges import ProofOfPossession
        hints = ProofOfPossession.Hints(
            jwk=KEY.public_key(), cert_fingerprints=(),
            certs=(), serial_numbers=(), subject_key_identifiers=(),
            issuers=(), authorized_for=())
        self.msg = ProofOfPossession(
            alg=jose.RS256, hints=hints,
            nonce=b'xD\xf9\xb9\xdbU\xed\xaa\x17\xf1y|\x81\x88\x99 ')

        self.jmsg_to = {
            'type': 'proofOfPossession',
            'alg': jose.RS256,
            'nonce': 'eET5udtV7aoX8Xl8gYiZIA',
            'hints': hints,
        }
        self.jmsg_from = {
            'type': 'proofOfPossession',
            'alg': jose.RS256.to_json(),
            'nonce': 'eET5udtV7aoX8Xl8gYiZIA',
            'hints': hints.to_json(),
        }

    def test_to_partial_json(self):
        self.assertEqual(self.jmsg_to, self.msg.to_partial_json())

    def test_from_json(self):
        from acme.challenges import ProofOfPossession
        self.assertEqual(
            self.msg, ProofOfPossession.from_json(self.jmsg_from))

    def test_from_json_hashable(self):
        from acme.challenges import ProofOfPossession
        hash(ProofOfPossession.from_json(self.jmsg_from))


class ProofOfPossessionResponseTest(unittest.TestCase):

    def setUp(self):
        # acme-spec uses a confusing example in which both signature
        # nonce and challenge nonce are the same, don't make the same
        # mistake here...
        signature = other.Signature(
            alg=jose.RS256, jwk=KEY.public_key(),
            sig=b'\xa7\xc1\xe7\xe82o\xbc\xcd\xd0\x1e\x010#Z|\xaf\x15\x83'
                b'\x94\x8f#\x9b\nQo(\x80\x15,\x08\xfcz\x1d\xfd\xfd.\xaap'
                b'\xfa\x06\xd1\xa2f\x8d8X2>%d\xbd%\xe1T\xdd\xaa0\x18\xde'
                b'\x99\x08\xf0\x0e{',
            nonce=b'\x99\xc7Q\xb3f2\xbc\xdci\xfe\xd6\x98k\xc67\xdf',
        )

        from acme.challenges import ProofOfPossessionResponse
        self.msg = ProofOfPossessionResponse(
            nonce=b'xD\xf9\xb9\xdbU\xed\xaa\x17\xf1y|\x81\x88\x99 ',
            signature=signature)

        self.jmsg_to = {
            'resource': 'challenge',
            'type': 'proofOfPossession',
            'nonce': 'eET5udtV7aoX8Xl8gYiZIA',
            'signature': signature,
        }
        self.jmsg_from = {
            'resource': 'challenge',
            'type': 'proofOfPossession',
            'nonce': 'eET5udtV7aoX8Xl8gYiZIA',
            'signature': signature.to_json(),
        }

    def test_verify(self):
        self.assertTrue(self.msg.verify())

    def test_to_partial_json(self):
        self.assertEqual(self.jmsg_to, self.msg.to_partial_json())

    def test_from_json(self):
        from acme.challenges import ProofOfPossessionResponse
        self.assertEqual(
            self.msg, ProofOfPossessionResponse.from_json(self.jmsg_from))

    def test_from_json_hashable(self):
        from acme.challenges import ProofOfPossessionResponse
        hash(ProofOfPossessionResponse.from_json(self.jmsg_from))


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
            payload=self.msg.update(token=b'x' * 20).json_dumps().encode('utf-8'),
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
