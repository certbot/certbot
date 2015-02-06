"""Tests for letsencrypt.acme.messages."""
import pkg_resources
import unittest

import Crypto.PublicKey.RSA
import mock

from letsencrypt.acme import errors
from letsencrypt.acme import jose
from letsencrypt.acme import other


KEY = Crypto.PublicKey.RSA.importKey(pkg_resources.resource_string(
    'letsencrypt.client.tests', 'testdata/rsa256_key.pem'))


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
                pass

        self.msg_cls = TestMessage

    @classmethod
    def _from_json(cls, jobj, validate=True):
        from letsencrypt.acme.messages import Message
        return Message.from_json(jobj, validate)

    def test_from_json_non_dict_fails(self):
        self.assertRaises(errors.ValidationError, self._from_json, [])

    def test_from_json_dict_no_type_fails(self):
        self.assertRaises(errors.ValidationError, self._from_json, {})

    def test_from_json_unknown_type_fails(self):
        self.assertRaises(errors.UnrecognnizedMessageTypeError,
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


class AuthorizationRequestTest(unittest.TestCase):

    def setUp(self):
        self.responses = [
            {'type': 'simpleHttps', 'path': 'Hf5GrX4Q7EBax9hc2jJnfw'},
            None,  # null
            {'type': 'recoveryToken', 'token': '23029d88d9e123e'},
        ]
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
            contact=[],
        )

        self.jmsg = {
            'type': 'authorizationRequest',
            'sessionID': 'aefoGaavieG9Wihuk2aufai3aeZ5EeW4',
            'nonce': '7Nbyb1lI6xPVI3Hg3aKSqQ',
            'responses': self.responses,
            'signature': signature,
        }

    def test_create(self):
        from letsencrypt.acme.messages import AuthorizationRequest
        self.assertEqual(self.msg, AuthorizationRequest.create(
            name='example.com', key=KEY, responses=self.responses,
            nonce='\xec\xd6\xf2oYH\xeb\x13\xd5#q\xe0\xdd\xa2\x92\xa9',
            session_id='aefoGaavieG9Wihuk2aufai3aeZ5EeW4',
            sig_nonce='\xab?\x08o\xe6\x81$\x9f\xa1\xc9\x025\x1c\x1b\xa5+'))

    def test_verify(self):
        self.assertTrue(self.msg.verify('example.com'))

    def test_to_json(self):
        self.assertEqual(self.msg.to_json(), self.jmsg)

    def test_from_json(self):
        from letsencrypt.acme.messages import AuthorizationRequest
        self.jmsg['signature'] = self.jmsg['signature'].to_json()
        self.jmsg['signature']['jwk'] = self.jmsg['signature']['jwk'].to_json()
        self.assertEqual(self.msg, AuthorizationRequest.from_json(self.jmsg))


class CertificateRequestTest(unittest.TestCase):

    def setUp(self):
        self.csr = 'TODO: real DER CSR?'
        signature = other.Signature(
            alg='RS256', jwk=jose.JWK(key=KEY.publickey()),
            sig='\x1cD\x157\x83\x14\xd7 \xeb\x02\xb3\xf6O\xb5\x99C]\x97'
                '\x94p\xa7\xe48\x13>\x06\xf9yd\xf9\xfe\xf8\xd1>\x9aKH'
                '\xd7\xba\xb9a1\xf5!p\x1b\xd7}\xbaj\xa7\xe3\xd9\xd9\t%'
                '\xbb\xba\xc9\x00\xdaW\x16\xe9',
            nonce='\xec\xd6\xf2oYH\xeb\x13\xd5#q\xe0\xdd\xa2\x92\xa9')

        from letsencrypt.acme.messages import CertificateRequest
        self.msg = CertificateRequest(csr=self.csr, signature=signature)

        self.jmsg = {
            'type': 'certificateRequest',
            'csr': 'VE9ETzogcmVhbCBERVIgQ1NSPw',
            'signature': signature,
        }

    def test_create(self):
        from letsencrypt.acme.messages import CertificateRequest
        self.assertEqual(self.msg, CertificateRequest.create(
            csr=self.csr, key=KEY,
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


class RevocationRequestTest(unittest.TestCase):

    def setUp(self):
        self.sig_nonce = '\xec\xd6\xf2oYH\xeb\x13\xd5#q\xe0\xdd\xa2\x92\xa9'

        self.nonce = '\xec\xd6\xf2oYH\xeb\x13\xd5#q\xe0\xdd\xa2\x92\xa9'
        self.certificate = 'TODO: real DER cert?'

        signature = other.Signature(
            alg='RS256', jwk=jose.JWK(key=KEY.publickey()),
            sig='\x00\x15\xc0\xd4\x8b2M\xa9S\\\x8a#\xc6a\xa7!A\xb2d\x04'
                '\xa6\xbe\xa1/M\x0f|\x8c\x9eJ\x16\xcd\x85N\xcc\x0b\x12k('
                '\xa8U\xdfS\xa9y\xfd\xfa.\xb3\xeblms\x9f,\xdf\xbb>7\xd9'
                '\xe5u\x8f\xbe',
            nonce=self.sig_nonce)

        from letsencrypt.acme.messages import RevocationRequest
        self.msg = RevocationRequest(
            certificate=self.certificate, signature=signature)

        self.jmsg = {
            'type': 'revocationRequest',
            'certificate': 'VE9ETzogcmVhbCBERVIgY2VydD8',
            'signature': signature,
        }

    def test_create(self):
        from letsencrypt.acme.messages import RevocationRequest
        RevocationRequest.create(
            certificate=self.certificate, key=KEY, sig_nonce=self.sig_nonce)

    def test_verify(self):
        self.assertTrue(self.msg.verify())

    def test_to_json(self):
        self.assertEqual(self.msg.to_json(), self.jmsg)

    def test_from_json(self):
        from letsencrypt.acme.messages import RevocationRequest
        self.jmsg['signature'] = self.jmsg['signature'].to_json()
        self.jmsg['signature']['jwk'] = self.jmsg['signature']['jwk'].to_json()
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
