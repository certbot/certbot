"""Tests for letsencrypt.acme.messages."""
import pkg_resources
import unittest

import jsonschema


class ACMEObjectValidateTest(unittest.TestCase):
    """Tests for letsencrypt.acme.messages.acme_object_validate."""

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

    def _call(self, json_string):
        from letsencrypt.acme.messages import acme_object_validate
        return acme_object_validate(json_string, self.schemata)

    def _test_fails(self, json_string):
        self.assertRaises(jsonschema.ValidationError, self._call, json_string)

    def test_non_dictionary_fails(self):
        self._test_fails('[]')

    def test_dict_without_type_fails(self):
        self._test_fails('{}')

    def test_unknown_type_fails(self):
        self._test_fails('{"type": "bar"}')

    def test_valid_returns_none(self):
        self.assertTrue(self._call('{"type": "foo"}') is None)

    def test_invalid_fails(self):
        self._test_fails('{"type": "foo", "price": "asd"}')


class PrettyTest(unittest.TestCase):  # pylint: disable=too-few-public-methods
    """Tests for letsencrypt.acme.messages.pretty."""

    @classmethod
    def _call(cls, json_string):
        from letsencrypt.acme.messages import pretty
        return pretty(json_string)

    def test_it(self):
        self.assertEqual(
            self._call('{"foo": {"bar": "baz"}}'),
            '{\n    "foo": {\n        "bar": "baz"\n    }\n}')


class MessageFactoriesTest(unittest.TestCase):
    """Tests for ACME message factories from letsencrypt.acme.messages."""

    def setUp(self):
        self.privkey = pkg_resources.resource_string(
            'letsencrypt.client.tests', 'testdata/rsa256_key.pem')
        self.nonce = '\xec\xd6\xf2oYH\xeb\x13\xd5#q\xe0\xdd\xa2\x92\xa9'
        self.b64nonce = '7Nbyb1lI6xPVI3Hg3aKSqQ'

    @classmethod
    def _validate(cls, msg):
        from letsencrypt.acme.messages import SCHEMATA
        jsonschema.validate(msg, SCHEMATA[msg['type']])

    def test_challenge_request(self):
        from letsencrypt.acme.messages import challenge_request
        msg = challenge_request('example.com')
        self._validate(msg)
        self.assertEqual(msg, {
            'type': 'challengeRequest',
            'identifier': 'example.com',
        })

    def test_authorization_request(self):
        from letsencrypt.acme.messages import authorization_request
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
        msg = authorization_request(
            'aefoGaavieG9Wihuk2aufai3aeZ5EeW4',
            'example.com',
            'czpsrF0KMH6dgajig3TGHw',
            responses,
            self.privkey,
            self.nonce,
        )

        self._validate(msg)
        self.assertEqual(
            msg.pop('signature')['sig'],
            'VkpReso87ogwGul2MGck96TkYs4QoblIgNthgrm9O7EBGlzCRCnTHnx'
            'bj6loqaC4f5bn1rgS927Gp1Kvbqnmqg'
        )
        self.assertEqual(msg, {
            'type': 'authorizationRequest',
            'sessionID': 'aefoGaavieG9Wihuk2aufai3aeZ5EeW4',
            'nonce': 'czpsrF0KMH6dgajig3TGHw',
            'responses': responses,
        })

    def test_certificate_request(self):
        from letsencrypt.acme.messages import certificate_request
        msg = certificate_request(
            'TODO: real DER CSR?', self.privkey, self.nonce)
        self._validate(msg)
        self.assertEqual(
            msg.pop('signature')['sig'],
            'HEQVN4MU1yDrArP2T7WZQ12XlHCn5DgTPgb5eWT5_vjRPppLSNe6uWE'
            'x9SFwG9d9umqn49nZCSW7uskA2lcW6Q'
        )
        self.assertEqual(msg, {
            'type': 'certificateRequest',
            'csr': 'VE9ETzogcmVhbCBERVIgQ1NSPw',
        })

    def test_revocation_request(self):
        from letsencrypt.acme.messages import revocation_request
        msg = revocation_request(
            'TODO: real DER cert?', self.privkey, self.nonce)
        self._validate(msg)
        self.assertEqual(
            msg.pop('signature')['sig'],
            'ABXA1IsyTalTXIojxmGnIUGyZASmvqEvTQ98jJ5KFs2FTswLEmsoqFX'
            'fU6l5_fous-tsbXOfLN-7PjfZ5XWPvg'
        )
        self.assertEqual(msg, {
            'type': 'revocationRequest',
            'certificate': 'VE9ETzogcmVhbCBERVIgY2VydD8',
        })

    def test_status_request(self):
        from letsencrypt.acme.messages import status_request
        msg = status_request(u'O7-s9MNq1siZHlgrMzi9_A')
        self._validate(msg)
        self.assertEqual(msg, {
            'type': 'statusRequest',
            'token': u'O7-s9MNq1siZHlgrMzi9_A',
        })


if __name__ == '__main__':
    unittest.main()
