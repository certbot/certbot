"""Tests for letsencrypt.acme.messages."""
import pkg_resources
import unittest

import Crypto.PublicKey.RSA
import mock

from letsencrypt.acme import errors

KEY = Crypto.PublicKey.RSA.importKey(pkg_resources.resource_string(
    'letsencrypt.client.tests', 'testdata/rsa256_key.pem'))


class MessageTest(unittest.TestCase):
    """Tests for letsencrypt.acme.messages.Message."""

    def setUp(self):
        self.schemata = {
            'foo': {
                'type': 'object',
                'properties': {
                    'price': {'type': 'number'},
                    'name': {'type': 'string'},
                },
            },
        }


    def _validate(self, json_object):
        from letsencrypt.acme.messages import Message
        return Message.validate(json_object, self.schemata)

    def test_validate_non_dictionary_fails(self):
        self.assertRaises(errors.ValidationError, self._validate, [])

    def test_validate_dict_without_type_fails(self):
        self.assertRaises(errors.ValidationError, self._validate, {})

    def test_validate_unknown_type_fails(self):
        self.assertRaises(errors.UnrecognnizedMessageTypeError,
                          self._validate, {'type': 'bar'})

    def test_validate_unregistered_type_fails(self):
        self.assertRaises(errors.UnrecognnizedMessageTypeError,
                          self._validate, {'type': 'foo'})

    @mock.patch('letsencrypt.acme.messages.Message.TYPES')
    def test_validate_invalid_fails(self, types):
        types.__getitem__.side_effect = lambda x: {'foo': 'bar'}[x]
        self.assertRaises(errors.SchemaValidationError,
                          self._validate, {'type': 'foo', 'price': 'asd'})

    @mock.patch('letsencrypt.acme.messages.Message.TYPES')
    def test_validate_valid_returns_cls(self, types):
        types.__getitem__.side_effect = lambda x: {'foo': 'bar'}[x]
        self.assertEqual(self._validate({'type': 'foo'}), 'bar')


class ChallengeRequestTest(unittest.TestCase):
    # pylint: disable=too-few-public-methods

    def test_it(self):
        from letsencrypt.acme.messages import ChallengeRequest
        msg = ChallengeRequest('example.com')

        jmsg = msg._fields_to_json()  # pylint: disable=protected-access
        self.assertEqual(jmsg, {
            'identifier': 'example.com',
        })


class AuthorizationRequestTest(unittest.TestCase):

    def setUp(self):
        self.nonce = '\xec\xd6\xf2oYH\xeb\x13\xd5#q\xe0\xdd\xa2\x92\xa9'
        self.b64nonce = '7Nbyb1lI6xPVI3Hg3aKSqQ'
        self.csr = 'TODO: real DER CSR?'

    def test_authorization_request(self):
        from letsencrypt.acme.messages import AuthorizationRequest
        responses = [
            {
                'type': 'simpleHttps',
                'path': 'Hf5GrX4Q7EBax9hc2jJnfw',
            },
            None,  # null
            {
                'type': 'recoveryToken',
                'token': '23029d88d9e123e',
            }
        ]
        msg = AuthorizationRequest.create(
            'aefoGaavieG9Wihuk2aufai3aeZ5EeW4',
            'czpsrF0KMH6dgajig3TGHw',
            responses,
            'example.com',
            KEY,
            self.nonce,
        )
        msg.verify('example.com')

        jmsg = msg._fields_to_json()  # pylint: disable=protected-access
        jmsg.pop('signature')
        self.assertEqual(jmsg, {
            'sessionID': 'aefoGaavieG9Wihuk2aufai3aeZ5EeW4',
            'nonce': 'czpsrF0KMH6dgajig3TGHw',
            'responses': responses,
        })


class CertificateRequestTest(unittest.TestCase):

    def setUp(self):
        self.nonce = '\xec\xd6\xf2oYH\xeb\x13\xd5#q\xe0\xdd\xa2\x92\xa9'
        self.b64nonce = '7Nbyb1lI6xPVI3Hg3aKSqQ'
        self.csr = 'TODO: real DER CSR?'

    def test_it(self):
        from letsencrypt.acme.messages import CertificateRequest
        msg = CertificateRequest.create(self.csr, KEY, self.nonce)
        self.assertTrue(msg.verify())

        jmsg = msg._fields_to_json()  # pylint: disable=protected-access
        jmsg.pop('signature')
        self.assertEqual(jmsg, {
            'csr': 'VE9ETzogcmVhbCBERVIgQ1NSPw',
        })


class RevocationRequestTest(unittest.TestCase):

    def setUp(self):
        self.nonce = '\xec\xd6\xf2oYH\xeb\x13\xd5#q\xe0\xdd\xa2\x92\xa9'
        self.b64nonce = '7Nbyb1lI6xPVI3Hg3aKSqQ'
        self.certificate = 'TODO: real DER cert?'

    def test_it(self):
        from letsencrypt.acme.messages import RevocationRequest
        msg = RevocationRequest.create(self.certificate, KEY, self.nonce)
        self.assertTrue(msg.verify())

        jmsg = msg._fields_to_json()  # pylint: disable=protected-access
        jmsg.pop('signature')
        self.assertEqual(jmsg, {
            'certificate': 'VE9ETzogcmVhbCBERVIgY2VydD8',
        })


class StatusRequestTest(unittest.TestCase):

    def setUp(self):
        from letsencrypt.acme.messages import StatusRequest
        self.token = u'O7-s9MNq1siZHlgrMzi9_A'
        self.msg = StatusRequest(self.token)
        self.jmsg = {
            'token': self.token,
        }

    def test_attributes(self):
        self.assertEqual(self.msg.token, self.token)

    def test_json(self):
        jmsg = self.msg._fields_to_json()  # pylint: disable=protected-access
        self.assertEqual(jmsg, self.jmsg)

        from letsencrypt.acme.messages import StatusRequest
        # pylint: disable=protected-access
        msg = StatusRequest._valid_from_json(self.jmsg)
        self.assertEqual(msg.token, self.msg.token)


if __name__ == '__main__':
    unittest.main()
