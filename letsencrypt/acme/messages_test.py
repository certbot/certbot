"""Tests for letsencrypt.acme.messages."""
import pkg_resources
import unittest

import Crypto.PublicKey.RSA
import M2Crypto.X509
import mock

from letsencrypt.acme import errors
from letsencrypt.acme import jose
from letsencrypt.acme import other


KEY = Crypto.PublicKey.RSA.importKey(pkg_resources.resource_string(
    'letsencrypt.client.tests', 'testdata/rsa256_key.pem'))
CERT = M2Crypto.X509.load_cert(pkg_resources.resource_filename(
    'letsencrypt.client.tests', 'testdata/cert.pem'))
CSR = M2Crypto.X509.load_request(pkg_resources.resource_filename(
    'letsencrypt.client.tests', 'testdata/csr.pem'))


class MessageTest(unittest.TestCase):
    """Tests for letsencrypt.acme.messages.Message."""

    def setUp(self):
        # pylint: disable=missing-docstring,too-few-public-methods
        from letsencrypt.acme.messages import Message
        class TestMessage(Message):
            acme_type = 'test'
            schema = {
                'type': 'object',
                'properties': {
                    'price': {'type': 'number'},
                    'name': {'type': 'string'},
                },
            }

            @classmethod
            def _from_valid_json(cls, jobj):
                return jobj

            def _fields_to_json(self):
                return {'foo': 'bar'}

        self.msg_cls = TestMessage

    def test_to_json(self):
        self.assertEqual(self.msg_cls().to_json(), {
            'type': 'test',
            'foo': 'bar',
        })

    def test_fields_to_json_not_implemented(self):
        from letsencrypt.acme.messages import Message
        # pylint: disable=protected-access
        self.assertRaises(NotImplementedError, Message()._fields_to_json)

    @classmethod
    def _from_json(cls, jobj, validate=True):
        from letsencrypt.acme.messages import Message
        return Message.from_json(jobj, validate)

    def test_from_json_non_dict_fails(self):
        self.assertRaises(errors.ValidationError, self._from_json, [])

    def test_from_json_dict_no_type_fails(self):
        self.assertRaises(errors.ValidationError, self._from_json, {})

    def test_from_json_unknown_type_fails(self):
        self.assertRaises(errors.UnrecognizedMessageTypeError,
                          self._from_json, {'type': 'bar'})

    @mock.patch('letsencrypt.acme.messages.Message.TYPES')
    def test_from_json_validate_errors(self, types):
        types.__getitem__.side_effect = lambda x: {'foo': self.msg_cls}[x]
        self.assertRaises(errors.SchemaValidationError,
                          self._from_json, {'type': 'foo', 'price': 'asd'})

    @mock.patch('letsencrypt.acme.messages.Message.TYPES')
    def test_from_json_valid_returns_cls(self, types):
        types.__getitem__.side_effect = lambda x: {'foo': self.msg_cls}[x]
        self.assertEqual(self._from_json({'type': 'foo'}, validate=False),
                         {'type': 'foo'})


class ChallengeTest(unittest.TestCase):

    def setUp(self):
        challenges = [
            {'type': 'simpleHttps', 'token': 'IlirfxKKXAsHtmzK29Pj8A'},
            {'type': 'dns', 'token': 'DGyRejmCefe7v4NfDGDKfA'},
            {'type': 'recoveryToken'},
        ]
        combinations = [[0, 2], [1, 2]]

        from letsencrypt.acme.messages import Challenge
        self.msg = Challenge(
            session_id='aefoGaavieG9Wihuk2aufai3aeZ5EeW4',
            nonce='\xec\xd6\xf2oYH\xeb\x13\xd5#q\xe0\xdd\xa2\x92\xa9',
            challenges=challenges, combinations=combinations)

        self.jmsg = {
            'type': 'challenge',
            'sessionID': 'aefoGaavieG9Wihuk2aufai3aeZ5EeW4',
            'nonce': '7Nbyb1lI6xPVI3Hg3aKSqQ',
            'challenges': challenges,
            'combinations': combinations,
        }

    def test_to_json(self):
        self.assertEqual(self.msg.to_json(), self.jmsg)

    def test_from_json(self):
        from letsencrypt.acme.messages import Challenge
        self.assertEqual(Challenge.from_json(self.jmsg), self.msg)

    def test_json_without_optionals(self):
        del self.jmsg['combinations']

        from letsencrypt.acme.messages import Challenge
        msg = Challenge.from_json(self.jmsg)

        self.assertEqual(msg.combinations, [])
        self.assertEqual(msg.to_json(), self.jmsg)


class ChallengeRequestTest(unittest.TestCase):

    def setUp(self):
        from letsencrypt.acme.messages import ChallengeRequest
        self.msg = ChallengeRequest(identifier='example.com')

        self.jmsg = {
            'type': 'challengeRequest',
            'identifier': 'example.com',
        }

    def test_to_json(self):
        self.assertEqual(self.msg.to_json(), self.jmsg)

    def test_from_json(self):
        from letsencrypt.acme.messages import ChallengeRequest
        self.assertEqual(ChallengeRequest.from_json(self.jmsg), self.msg)


class AuthorizationTest(unittest.TestCase):

    def setUp(self):
        jwk = jose.JWK(key=KEY.publickey())

        from letsencrypt.acme.messages import Authorization
        self.msg = Authorization(recovery_token='tok', jwk=jwk,
                                 identifier='example.com')

        self.jmsg = {
            'type': 'authorization',
            'recoveryToken': 'tok',
            'identifier': 'example.com',
            'jwk': jwk,
        }

    def test_to_json(self):
        self.assertEqual(self.msg.to_json(), self.jmsg)

    def test_from_json(self):
        self.jmsg['jwk'] = self.jmsg['jwk'].to_json()

        from letsencrypt.acme.messages import Authorization
        self.assertEqual(Authorization.from_json(self.jmsg), self.msg)

    def test_json_without_optionals(self):
        del self.jmsg['recoveryToken']
        del self.jmsg['identifier']
        del self.jmsg['jwk']

        from letsencrypt.acme.messages import Authorization
        msg = Authorization.from_json(self.jmsg)

        self.assertTrue(msg.recovery_token is None)
        self.assertTrue(msg.identifier is None)
        self.assertTrue(msg.jwk is None)
        self.assertEqual(self.jmsg, msg.to_json())


class AuthorizationRequestTest(unittest.TestCase):

    def setUp(self):
        self.responses = [
            {'type': 'simpleHttps', 'path': 'Hf5GrX4Q7EBax9hc2jJnfw'},
            None,  # null
            {'type': 'recoveryToken', 'token': '23029d88d9e123e'},
        ]
        self.contact = ["mailto:cert-admin@example.com", "tel:+12025551212"]
        signature = other.Signature(
            alg='RS256', jwk=jose.JWK(key=KEY.publickey()),
            sig='-v\xd8\xc2\xa3\xba0\xd6\x92\x16\xb5.\xbe\xa1[\x04\xbe'
                '\x1b\xa1X\xd2)\x18\x94\x8f\xd7\xd0\xc0\xbbcI`W\xdf v'
                '\xe4\xed\xe8\x03J\xe8\xc8<?\xc8W\x94\x94cj(\xe7\xaa$'
                '\x92\xe9\x96\x11\xc2\xefx\x0bR',
            nonce='\xab?\x08o\xe6\x81$\x9f\xa1\xc9\x025\x1c\x1b\xa5+')

        from letsencrypt.acme.messages import AuthorizationRequest
        self.msg = AuthorizationRequest(
            session_id='aefoGaavieG9Wihuk2aufai3aeZ5EeW4',
            nonce='\xec\xd6\xf2oYH\xeb\x13\xd5#q\xe0\xdd\xa2\x92\xa9',
            responses=self.responses,
            signature=signature,
            contact=self.contact,
        )

        self.jmsg_to = {
            'type': 'authorizationRequest',
            'sessionID': 'aefoGaavieG9Wihuk2aufai3aeZ5EeW4',
            'nonce': '7Nbyb1lI6xPVI3Hg3aKSqQ',
            'responses': self.responses,
            'signature': signature,
            'contact': self.contact,
        }
        self.jmsg_from = {
            'type': 'authorizationRequest',
            'sessionID': 'aefoGaavieG9Wihuk2aufai3aeZ5EeW4',
            'nonce': '7Nbyb1lI6xPVI3Hg3aKSqQ',
            'responses': self.responses,
            'signature': signature.to_json(),
            'contact': self.contact,
        }
        self.jmsg_from['signature']['jwk'] = self.jmsg_from[
            'signature']['jwk'].to_json()

    def test_create(self):
        from letsencrypt.acme.messages import AuthorizationRequest
        self.assertEqual(self.msg, AuthorizationRequest.create(
            name='example.com', key=KEY, responses=self.responses,
            nonce='\xec\xd6\xf2oYH\xeb\x13\xd5#q\xe0\xdd\xa2\x92\xa9',
            session_id='aefoGaavieG9Wihuk2aufai3aeZ5EeW4',
            sig_nonce='\xab?\x08o\xe6\x81$\x9f\xa1\xc9\x025\x1c\x1b\xa5+',
            contact=self.contact))

    def test_verify(self):
        self.assertTrue(self.msg.verify('example.com'))

    def test_to_json(self):
        self.assertEqual(self.msg.to_json(), self.jmsg_to)

    def test_from_json(self):
        from letsencrypt.acme.messages import AuthorizationRequest
        self.assertEqual(
            self.msg, AuthorizationRequest.from_json(self.jmsg_from))

    def test_json_without_optionals(self):
        del self.jmsg_from['contact']
        del self.jmsg_to['contact']

        from letsencrypt.acme.messages import AuthorizationRequest
        msg = AuthorizationRequest.from_json(self.jmsg_from)

        self.assertEqual(msg.contact, [])
        self.assertEqual(self.jmsg_to, msg.to_json())


class CertificateTest(unittest.TestCase):

    def setUp(self):
        refresh = 'https://example.com/refresh/Dr8eAwTVQfSS/'

        from letsencrypt.acme.messages import Certificate
        self.msg = Certificate(
            certificate=CERT, chain=[CERT], refresh=refresh)

        self.jmsg = {
            'type': 'certificate',
            'certificate': jose.b64encode(CERT.as_der()),
            'chain': [jose.b64encode(CERT.as_der())],
            'refresh': refresh,
        }

    def test_to_json(self):
        self.assertEqual(self.msg.to_json(), self.jmsg)

    def test_from_json(self):
        from letsencrypt.acme.messages import Certificate
        self.assertEqual(Certificate.from_json(self.jmsg), self.msg)

    def test_json_without_optionals(self):
        del self.jmsg['chain']
        del self.jmsg['refresh']

        from letsencrypt.acme.messages import Certificate
        msg = Certificate.from_json(self.jmsg)

        self.assertEqual(msg.chain, [])
        self.assertTrue(msg.refresh is None)
        self.assertEqual(self.jmsg, msg.to_json())


class CertificateRequestTest(unittest.TestCase):

    def setUp(self):
        signature = other.Signature(
            alg='RS256', jwk=jose.JWK(key=KEY.publickey()),
            sig='\x15\xed\x84\xaa:\xf2DO\x0e9 \xbcg\xf8\xc0\xcf\x87\x9a'
                '\x95\xeb\xffT[\x84[\xec\x85\x7f\x8eK\xe9\xc2\x12\xc8Q'
                '\xafo\xc6h\x07\xba\xa6\xdf\xd1\xa7"$\xba=Z\x13n\x14\x0b'
                'k\xfe\xee\xb4\xe4\xc8\x05\x9a\x08\xa7',
            nonce='\xec\xd6\xf2oYH\xeb\x13\xd5#q\xe0\xdd\xa2\x92\xa9')

        from letsencrypt.acme.messages import CertificateRequest
        self.msg = CertificateRequest(csr=CSR, signature=signature)

        self.jmsg = {
            'type': 'certificateRequest',
            'csr': jose.b64encode(CSR.as_der()),
            'signature': signature,
        }

    def test_create(self):
        from letsencrypt.acme.messages import CertificateRequest
        self.assertEqual(self.msg, CertificateRequest.create(
            csr=CSR, key=KEY,
            sig_nonce='\xec\xd6\xf2oYH\xeb\x13\xd5#q\xe0\xdd\xa2\x92\xa9'))

    def test_verify(self):
        self.assertTrue(self.msg.verify())

    def test_to_json(self):
        self.assertEqual(self.msg.to_json(), self.jmsg)

    def test_from_json(self):
        from letsencrypt.acme.messages import CertificateRequest
        self.jmsg['signature'] = self.jmsg['signature'].to_json()
        self.jmsg['signature']['jwk'] = self.jmsg['signature']['jwk'].to_json()
        self.assertEqual(self.msg, CertificateRequest.from_json(self.jmsg))


class DeferTest(unittest.TestCase):

    def setUp(self):
        from letsencrypt.acme.messages import Defer
        self.msg = Defer(
            token='O7-s9MNq1siZHlgrMzi9_A', interval=60,
            message='Warming up the HSM')

        self.jmsg = {
            'type': 'defer',
            'token': 'O7-s9MNq1siZHlgrMzi9_A',
            'interval': 60,
            'message': 'Warming up the HSM',
        }

    def test_to_json(self):
        self.assertEqual(self.msg.to_json(), self.jmsg)

    def test_from_json(self):
        from letsencrypt.acme.messages import Defer
        self.assertEqual(Defer.from_json(self.jmsg), self.msg)

    def test_json_without_optionals(self):
        del self.jmsg['interval']
        del self.jmsg['message']

        from letsencrypt.acme.messages import Defer
        msg = Defer.from_json(self.jmsg)

        self.assertTrue(msg.interval is None)
        self.assertTrue(msg.message is None)
        self.assertEqual(self.jmsg, msg.to_json())


class ErrorTest(unittest.TestCase):

    def setUp(self):
        from letsencrypt.acme.messages import Error
        self.msg = Error(
            error='badCSR', message='RSA keys must be at least 2048 bits long',
            more_info='https://ca.example.com/documentation/csr-requirements')

        self.jmsg = {
            'type': 'error',
            'error': 'badCSR',
            'message':'RSA keys must be at least 2048 bits long',
            'moreInfo': 'https://ca.example.com/documentation/csr-requirements',
        }

    def test_to_json(self):
        self.assertEqual(self.msg.to_json(), self.jmsg)

    def test_from_json(self):
        from letsencrypt.acme.messages import Error
        self.assertEqual(Error.from_json(self.jmsg), self.msg)

    def test_json_without_optionals(self):
        del self.jmsg['message']
        del self.jmsg['moreInfo']

        from letsencrypt.acme.messages import Error
        msg = Error.from_json(self.jmsg)

        self.assertTrue(msg.message is None)
        self.assertTrue(msg.more_info is None)
        self.assertEqual(self.jmsg, msg.to_json())


class RevocationTest(unittest.TestCase):

    def setUp(self):
        from letsencrypt.acme.messages import Revocation
        self.msg = Revocation()

        self.jmsg = {
            'type': 'revocation',
        }

    def test_to_json(self):
        self.assertEqual(self.msg.to_json(), self.jmsg)

    def test_from_json(self):
        from letsencrypt.acme.messages import Revocation
        self.assertEqual(Revocation.from_json(self.jmsg), self.msg)


class RevocationRequestTest(unittest.TestCase):

    def setUp(self):
        self.sig_nonce = '\xec\xd6\xf2oYH\xeb\x13\xd5#q\xe0\xdd\xa2\x92\xa9'

        signature = other.Signature(
            alg='RS256', jwk=jose.JWK(key=KEY.publickey()),
            sig='eJ\xfe\x12"U\x87\x8b\xbf/ ,\xdeP\xb2\xdc1\xb00\xe5\x1dB'
                '\xfch<\xc6\x9eH@!\x1c\x16\xb2\x0b_\xc4\xddP\x89\xc8\xce?'
                '\x16g\x069I\xb9\xb3\x91\xb9\x0e$3\x9f\x87\x8e\x82\xca\xc5'
                's\xd9\xd0\xe7',
            nonce=self.sig_nonce)

        from letsencrypt.acme.messages import RevocationRequest
        self.msg = RevocationRequest(certificate=CERT, signature=signature)

        self.jmsg = {
            'type': 'revocationRequest',
            'certificate': jose.b64encode(CERT.as_der()),
            'signature': signature,
        }

    def test_create(self):
        from letsencrypt.acme.messages import RevocationRequest
        self.assertEqual(self.msg, RevocationRequest.create(
            certificate=CERT, key=KEY, sig_nonce=self.sig_nonce))

    def test_verify(self):
        self.assertTrue(self.msg.verify())

    def test_to_json(self):
        self.assertEqual(self.msg.to_json(), self.jmsg)

    def test_from_json(self):
        self.jmsg['signature'] = self.jmsg['signature'].to_json()
        self.jmsg['signature']['jwk'] = self.jmsg['signature']['jwk'].to_json()

        from letsencrypt.acme.messages import RevocationRequest
        self.assertEqual(self.msg, RevocationRequest.from_json(self.jmsg))


class StatusRequestTest(unittest.TestCase):

    def setUp(self):
        from letsencrypt.acme.messages import StatusRequest
        self.msg = StatusRequest(token=u'O7-s9MNq1siZHlgrMzi9_A')
        self.jmsg = {
            'type': 'statusRequest',
            'token': u'O7-s9MNq1siZHlgrMzi9_A',
        }

    def test_to_json(self):
        self.assertEqual(self.msg.to_json(), self.jmsg)

    def test_from_json(self):
        from letsencrypt.acme.messages import StatusRequest
        self.assertEqual(StatusRequest.from_json(self.jmsg), self.msg)


if __name__ == '__main__':
    unittest.main()
