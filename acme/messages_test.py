"""Tests for acme.messages."""
import os
import pkg_resources
import unittest

import Crypto.PublicKey.RSA
import M2Crypto

from acme import challenges
from acme import errors
from acme import jose
from acme import other


KEY = jose.HashableRSAKey(Crypto.PublicKey.RSA.importKey(
    pkg_resources.resource_string(
        'acme.jose', os.path.join('testdata', 'rsa512_key.pem'))))
CERT = jose.ComparableX509(M2Crypto.X509.load_cert(
    pkg_resources.resource_filename(
        'letsencrypt.tests', os.path.join('testdata', 'cert.pem'))))
CSR = jose.ComparableX509(M2Crypto.X509.load_request(
    pkg_resources.resource_filename(
        'letsencrypt.tests', os.path.join('testdata', 'csr.pem'))))
CSR2 = jose.ComparableX509(M2Crypto.X509.load_request(
    pkg_resources.resource_filename(
        'acme.jose', os.path.join('testdata', 'csr2.pem'))))


class MessageTest(unittest.TestCase):
    """Tests for acme.messages.Message."""

    def setUp(self):
        # pylint: disable=missing-docstring,too-few-public-methods
        from acme.messages import Message

        class MockParentMessage(Message):
            # pylint: disable=abstract-method
            TYPES = {}

        @MockParentMessage.register
        class MockMessage(MockParentMessage):
            typ = 'test'
            schema = {
                'type': 'object',
                'properties': {
                    'price': {'type': 'number'},
                    'name': {'type': 'string'},
                },
            }
            price = jose.Field('price')
            name = jose.Field('name')

        self.parent_cls = MockParentMessage
        self.msg = MockMessage(price=123, name='foo')

    def test_from_json_validates(self):
        self.assertRaises(errors.SchemaValidationError,
                          self.parent_cls.from_json,
                          {'type': 'test', 'price': 'asd'})


class ChallengeTest(unittest.TestCase):

    def setUp(self):
        challs = (
            challenges.SimpleHTTP(token='IlirfxKKXAsHtmzK29Pj8A'),
            challenges.DNS(token='DGyRejmCefe7v4NfDGDKfA'),
            challenges.RecoveryToken(),
        )
        combinations = ((0, 2), (1, 2))

        from acme.messages import Challenge
        self.msg = Challenge(
            session_id='aefoGaavieG9Wihuk2aufai3aeZ5EeW4',
            nonce='\xec\xd6\xf2oYH\xeb\x13\xd5#q\xe0\xdd\xa2\x92\xa9',
            challenges=challs, combinations=combinations)

        self.jmsg_to = {
            'type': 'challenge',
            'sessionID': 'aefoGaavieG9Wihuk2aufai3aeZ5EeW4',
            'nonce': '7Nbyb1lI6xPVI3Hg3aKSqQ',
            'challenges': challs,
            'combinations': combinations,
        }

        self.jmsg_from = {
            'type': 'challenge',
            'sessionID': 'aefoGaavieG9Wihuk2aufai3aeZ5EeW4',
            'nonce': '7Nbyb1lI6xPVI3Hg3aKSqQ',
            'challenges': [chall.to_json() for chall in challs],
            'combinations': [[0, 2], [1, 2]], # TODO array tuples
        }

    def test_resolved_combinations(self):
        self.assertEqual(self.msg.resolved_combinations, (
            (
                challenges.SimpleHTTP(token='IlirfxKKXAsHtmzK29Pj8A'),
                challenges.RecoveryToken()
            ),
            (
                challenges.DNS(token='DGyRejmCefe7v4NfDGDKfA'),
                challenges.RecoveryToken(),
            )
        ))

    def test_to_partial_json(self):
        self.assertEqual(self.msg.to_partial_json(), self.jmsg_to)

    def test_from_json(self):
        from acme.messages import Challenge
        self.assertEqual(Challenge.from_json(self.jmsg_from), self.msg)

    def test_json_without_optionals(self):
        del self.jmsg_from['combinations']
        del self.jmsg_to['combinations']

        from acme.messages import Challenge
        msg = Challenge.from_json(self.jmsg_from)

        self.assertEqual(msg.combinations, ())
        self.assertEqual(msg.to_partial_json(), self.jmsg_to)


class ChallengeRequestTest(unittest.TestCase):

    def setUp(self):
        from acme.messages import ChallengeRequest
        self.msg = ChallengeRequest(identifier='example.com')

        self.jmsg = {
            'type': 'challengeRequest',
            'identifier': 'example.com',
        }

    def test_to_partial_json(self):
        self.assertEqual(self.msg.to_partial_json(), self.jmsg)

    def test_from_json(self):
        from acme.messages import ChallengeRequest
        self.assertEqual(ChallengeRequest.from_json(self.jmsg), self.msg)


class AuthorizationTest(unittest.TestCase):

    def setUp(self):
        jwk = jose.JWKRSA(key=KEY.publickey())

        from acme.messages import Authorization
        self.msg = Authorization(recovery_token='tok', jwk=jwk,
                                 identifier='example.com')

        self.jmsg = {
            'type': 'authorization',
            'recoveryToken': 'tok',
            'identifier': 'example.com',
            'jwk': jwk,
        }

    def test_to_partial_json(self):
        self.assertEqual(self.msg.to_partial_json(), self.jmsg)

    def test_from_json(self):
        self.jmsg['jwk'] = self.jmsg['jwk'].to_partial_json()

        from acme.messages import Authorization
        self.assertEqual(Authorization.from_json(self.jmsg), self.msg)

    def test_json_without_optionals(self):
        del self.jmsg['recoveryToken']
        del self.jmsg['identifier']
        del self.jmsg['jwk']

        from acme.messages import Authorization
        msg = Authorization.from_json(self.jmsg)

        self.assertTrue(msg.recovery_token is None)
        self.assertTrue(msg.identifier is None)
        self.assertTrue(msg.jwk is None)
        self.assertEqual(self.jmsg, msg.to_partial_json())


class AuthorizationRequestTest(unittest.TestCase):

    def setUp(self):
        self.responses = (
            challenges.SimpleHTTPResponse(path='Hf5GrX4Q7EBax9hc2jJnfw'),
            None,  # null
            challenges.RecoveryTokenResponse(token='23029d88d9e123e'),
        )
        self.contact = ("mailto:cert-admin@example.com", "tel:+12025551212")
        signature = other.Signature(
            alg=jose.RS256, jwk=jose.JWKRSA(key=KEY.publickey()),
            sig='-v\xd8\xc2\xa3\xba0\xd6\x92\x16\xb5.\xbe\xa1[\x04\xbe'
                '\x1b\xa1X\xd2)\x18\x94\x8f\xd7\xd0\xc0\xbbcI`W\xdf v'
                '\xe4\xed\xe8\x03J\xe8\xc8<?\xc8W\x94\x94cj(\xe7\xaa$'
                '\x92\xe9\x96\x11\xc2\xefx\x0bR',
            nonce='\xab?\x08o\xe6\x81$\x9f\xa1\xc9\x025\x1c\x1b\xa5+')

        from acme.messages import AuthorizationRequest
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
            'responses': [None if response is None else response.to_json()
                          for response in self.responses],
            'signature': signature.to_json(),
            # TODO: schema validation doesn't recognize tuples as
            # arrays :(
            'contact': list(self.contact),
        }

    def test_create(self):
        from acme.messages import AuthorizationRequest
        self.assertEqual(self.msg, AuthorizationRequest.create(
            name='example.com', key=KEY, responses=self.responses,
            nonce='\xec\xd6\xf2oYH\xeb\x13\xd5#q\xe0\xdd\xa2\x92\xa9',
            session_id='aefoGaavieG9Wihuk2aufai3aeZ5EeW4',
            sig_nonce='\xab?\x08o\xe6\x81$\x9f\xa1\xc9\x025\x1c\x1b\xa5+',
            contact=self.contact))

    def test_verify(self):
        self.assertTrue(self.msg.verify('example.com'))

    def test_to_partial_json(self):
        self.assertEqual(self.msg.to_partial_json(), self.jmsg_to)

    def test_from_json(self):
        from acme.messages import AuthorizationRequest
        self.assertEqual(
            self.msg, AuthorizationRequest.from_json(self.jmsg_from))

    def test_json_without_optionals(self):
        del self.jmsg_from['contact']
        del self.jmsg_to['contact']

        from acme.messages import AuthorizationRequest
        msg = AuthorizationRequest.from_json(self.jmsg_from)

        self.assertEqual(msg.contact, ())
        self.assertEqual(self.jmsg_to, msg.to_partial_json())


class CertificateTest(unittest.TestCase):

    def setUp(self):
        refresh = 'https://example.com/refresh/Dr8eAwTVQfSS/'

        from acme.messages import Certificate
        self.msg = Certificate(
            certificate=CERT, chain=(CERT,), refresh=refresh)

        self.jmsg_to = {
            'type': 'certificate',
            'certificate': jose.b64encode(CERT.as_der()),
            'chain': (jose.b64encode(CERT.as_der()),),
            'refresh': refresh,
        }
        self.jmsg_from = self.jmsg_to.copy()
        # TODO: schema validation array tuples
        self.jmsg_from['chain'] = list(self.jmsg_from['chain'])

    def test_to_partial_json(self):
        self.assertEqual(self.msg.to_partial_json(), self.jmsg_to)

    def test_from_json(self):
        from acme.messages import Certificate
        self.assertEqual(Certificate.from_json(self.jmsg_from), self.msg)

    def test_json_without_optionals(self):
        del self.jmsg_from['chain']
        del self.jmsg_from['refresh']
        del self.jmsg_to['chain']
        del self.jmsg_to['refresh']

        from acme.messages import Certificate
        msg = Certificate.from_json(self.jmsg_from)

        self.assertEqual(msg.chain, ())
        self.assertTrue(msg.refresh is None)
        self.assertEqual(self.jmsg_to, msg.to_partial_json())


class CertificateRequestTest(unittest.TestCase):

    def setUp(self):
        signature = other.Signature(
            alg=jose.RS256, jwk=jose.JWKRSA(key=KEY.publickey()),
            sig='\x15\xed\x84\xaa:\xf2DO\x0e9 \xbcg\xf8\xc0\xcf\x87\x9a'
                '\x95\xeb\xffT[\x84[\xec\x85\x7f\x8eK\xe9\xc2\x12\xc8Q'
                '\xafo\xc6h\x07\xba\xa6\xdf\xd1\xa7"$\xba=Z\x13n\x14\x0b'
                'k\xfe\xee\xb4\xe4\xc8\x05\x9a\x08\xa7',
            nonce='\xec\xd6\xf2oYH\xeb\x13\xd5#q\xe0\xdd\xa2\x92\xa9')

        from acme.messages import CertificateRequest
        self.msg = CertificateRequest(csr=CSR, signature=signature)

        self.jmsg_to = {
            'type': 'certificateRequest',
            'csr': jose.b64encode(CSR.as_der()),
            'signature': signature,
        }
        self.jmsg_from = self.jmsg_to.copy()
        self.jmsg_from['signature'] = self.jmsg_from['signature'].to_json()

    def test_create(self):
        from acme.messages import CertificateRequest
        self.assertEqual(self.msg, CertificateRequest.create(
            csr=CSR, key=KEY,
            sig_nonce='\xec\xd6\xf2oYH\xeb\x13\xd5#q\xe0\xdd\xa2\x92\xa9'))

    def test_verify(self):
        self.assertTrue(self.msg.verify())

    def test_to_partial_json(self):
        self.assertEqual(self.msg.to_partial_json(), self.jmsg_to)

    def test_from_json(self):
        from acme.messages import CertificateRequest
        self.assertEqual(self.msg, CertificateRequest.from_json(self.jmsg_from))


class DeferTest(unittest.TestCase):

    def setUp(self):
        from acme.messages import Defer
        self.msg = Defer(
            token='O7-s9MNq1siZHlgrMzi9_A', interval=60,
            message='Warming up the HSM')

        self.jmsg = {
            'type': 'defer',
            'token': 'O7-s9MNq1siZHlgrMzi9_A',
            'interval': 60,
            'message': 'Warming up the HSM',
        }

    def test_to_partial_json(self):
        self.assertEqual(self.msg.to_partial_json(), self.jmsg)

    def test_from_json(self):
        from acme.messages import Defer
        self.assertEqual(Defer.from_json(self.jmsg), self.msg)

    def test_json_without_optionals(self):
        del self.jmsg['interval']
        del self.jmsg['message']

        from acme.messages import Defer
        msg = Defer.from_json(self.jmsg)

        self.assertTrue(msg.interval is None)
        self.assertTrue(msg.message is None)
        self.assertEqual(self.jmsg, msg.to_partial_json())


class ErrorTest(unittest.TestCase):

    def setUp(self):
        from acme.messages import Error
        self.msg = Error(
            error='badCSR', message='RSA keys must be at least 2048 bits long',
            more_info='https://ca.example.com/documentation/csr-requirements')

        self.jmsg = {
            'type': 'error',
            'error': 'badCSR',
            'message':'RSA keys must be at least 2048 bits long',
            'moreInfo': 'https://ca.example.com/documentation/csr-requirements',
        }

    def test_to_partial_json(self):
        self.assertEqual(self.msg.to_partial_json(), self.jmsg)

    def test_from_json(self):
        from acme.messages import Error
        self.assertEqual(Error.from_json(self.jmsg), self.msg)

    def test_json_without_optionals(self):
        del self.jmsg['message']
        del self.jmsg['moreInfo']

        from acme.messages import Error
        msg = Error.from_json(self.jmsg)

        self.assertTrue(msg.message is None)
        self.assertTrue(msg.more_info is None)
        self.assertEqual(self.jmsg, msg.to_partial_json())


class RevocationTest(unittest.TestCase):

    def setUp(self):
        from acme.messages import Revocation
        self.msg = Revocation()
        self.jmsg = {'type': 'revocation'}

    def test_to_partial_json(self):
        self.assertEqual(self.msg.to_partial_json(), self.jmsg)

    def test_from_json(self):
        from acme.messages import Revocation
        self.assertEqual(Revocation.from_json(self.jmsg), self.msg)


class RevocationRequestTest(unittest.TestCase):

    def setUp(self):
        self.sig_nonce = '\xec\xd6\xf2oYH\xeb\x13\xd5#q\xe0\xdd\xa2\x92\xa9'

        signature = other.Signature(
            alg=jose.RS256, jwk=jose.JWKRSA(key=KEY.publickey()),
            sig='eJ\xfe\x12"U\x87\x8b\xbf/ ,\xdeP\xb2\xdc1\xb00\xe5\x1dB'
                '\xfch<\xc6\x9eH@!\x1c\x16\xb2\x0b_\xc4\xddP\x89\xc8\xce?'
                '\x16g\x069I\xb9\xb3\x91\xb9\x0e$3\x9f\x87\x8e\x82\xca\xc5'
                's\xd9\xd0\xe7',
            nonce=self.sig_nonce)

        from acme.messages import RevocationRequest
        self.msg = RevocationRequest(certificate=CERT, signature=signature)

        self.jmsg_to = {
            'type': 'revocationRequest',
            'certificate': jose.b64encode(CERT.as_der()),
            'signature': signature,
        }
        self.jmsg_from = self.jmsg_to.copy()
        self.jmsg_from['signature'] = self.jmsg_from['signature'].to_json()

    def test_create(self):
        from acme.messages import RevocationRequest
        self.assertEqual(self.msg, RevocationRequest.create(
            certificate=CERT, key=KEY, sig_nonce=self.sig_nonce))

    def test_verify(self):
        self.assertTrue(self.msg.verify())

    def test_to_partial_json(self):
        self.assertEqual(self.msg.to_partial_json(), self.jmsg_to)

    def test_from_json(self):
        from acme.messages import RevocationRequest
        self.assertEqual(self.msg, RevocationRequest.from_json(self.jmsg_from))


class StatusRequestTest(unittest.TestCase):

    def setUp(self):
        from acme.messages import StatusRequest
        self.msg = StatusRequest(token=u'O7-s9MNq1siZHlgrMzi9_A')
        self.jmsg = {
            'type': 'statusRequest',
            'token': u'O7-s9MNq1siZHlgrMzi9_A',
        }

    def test_to_partial_json(self):
        self.assertEqual(self.msg.to_partial_json(), self.jmsg)

    def test_from_json(self):
        from acme.messages import StatusRequest
        self.assertEqual(StatusRequest.from_json(self.jmsg), self.msg)


if __name__ == '__main__':
    unittest.main()  # pragma: no cover
