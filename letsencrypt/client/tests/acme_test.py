"""Tests for letsencrypt.client.acme."""
import unittest

import jsonschema


class ACMEObjectValidateTest(unittest.TestCase):
    """Tests for letsencrypt.client.acme.acme_object_validate."""

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
        from letsencrypt.client.acme import acme_object_validate
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


class PrettyTest(unittest.TestCase):
    """Tests for letsencrypt.client.acme.pretty."""

    def _call(self, json_string):
        from letsencrypt.client.acme import pretty
        return pretty(json_string)

    def test_it(self):
        self.assertEqual(
            self._call('{"foo": {"bar": "baz"}}'),
            '{\n    "foo": {\n        "bar": "baz"\n    }\n}')


class MessageFactoriesTest(unittest.TestCase):
    """Tests for ACME message factories from letsencrypt.client.acme."""

    def setUp(self):
        self.privkey = """-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBAKx1c7RR7R/drnBSQ/zfx1vQLHUbFLh1AQQQ5R8DZUXd36efNK79
vukFhN9HFoHZiUvOjm0c+pVE6K+EdE/twuUCAwEAAQJAMbrEnJCrQe8YqAbw1/Bn
elAzIamndfE3U8bTavf9sgFpS4HL83rhd6PDbvx81ucaJAT/5x048fM/nFl4fzAc
mQIhAOF/a9o3EIsDKEmUl+Z1OaOiUxDF3kqWSmALEsmvDhwXAiEAw8ljV5RO/rUp
Zu2YMDFq3MKpyyMgBIJ8CxmGRc6gCmMCIGRQzkcmhfqBrhOFwkmozrqIBRIKJIjj
8TRm2LXWZZ2DAiAqVO7PztdNpynugUy4jtbGKKjBrTSNBRGA7OHlUgm0dQIhALQq
6oGU29Vxlvt3k0vmiRKU4AVfLyNXIGtcWcNG46h/
-----END RSA PRIVATE KEY-----"""
        self.nonce = '\xec\xd6\xf2oYH\xeb\x13\xd5#q\xe0\xdd\xa2\x92\xa9'
        self.b64nonce = '7Nbyb1lI6xPVI3Hg3aKSqQ'

    def _validate(self, msg):
        from letsencrypt.client.acme import SCHEMATA
        jsonschema.validate(msg, SCHEMATA[msg['type']])

    def _signature(self, sig):
        return {
            'nonce': self.b64nonce,
            'alg': 'RS256',
            'jwk': {
                'kty': 'RSA',
                'e': 'AQAB',
                'n': 'rHVztFHtH92ucFJD_N_HW9AsdRsUuHUBBBDlHwNlRd3fp5'
                     '80rv2-6QWE30cWgdmJS86ObRz6lUTor4R0T-3C5Q',
            },
            'sig': sig,
        }

    def test_challenge_request(self):
        from letsencrypt.client.acme import challenge_request
        msg = challenge_request('example.com')
        self.assertEqual(msg, {
            'type': 'challengeRequest',
            'identifier': 'example.com',
        })
        self._validate(msg)

    def test_authorization_request(self):
        from letsencrypt.client.acme import authorization_request
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

        self.assertEqual(msg, {
            'type': 'authorizationRequest',
            'sessionID': 'aefoGaavieG9Wihuk2aufai3aeZ5EeW4',
            'nonce': 'czpsrF0KMH6dgajig3TGHw',
            'signature': self._signature(
                'VkpReso87ogwGul2MGck96TkYs4QoblIgNthgrm9O7EBGlzCRCnTHnx'
                'bj6loqaC4f5bn1rgS927Gp1Kvbqnmqg'),
            'responses': responses,
        })
        self._validate(msg)

    def test_certificate_request(self):
        from letsencrypt.client.acme import certificate_request
        msg = certificate_request(
            'TODO: real DER CSR?', self.privkey, self.nonce)
        self.assertEqual(msg, {
            'type': 'certificateRequest',
            'csr': 'VE9ETzogcmVhbCBERVIgQ1NSPw',
            'signature': self._signature(
                'HEQVN4MU1yDrArP2T7WZQ12XlHCn5DgTPgb5eWT5_vjRPppLSNe6uWE'
                'x9SFwG9d9umqn49nZCSW7uskA2lcW6Q'),
        })
        self._validate(msg)

    def test_revocation_request(self):
        from letsencrypt.client.acme import revocation_request
        msg = revocation_request(
            'TODO: real DER cert?', self.privkey, self.nonce)
        self.assertEqual(msg, {
            'type': 'revocationRequest',
            'certificate': 'VE9ETzogcmVhbCBERVIgY2VydD8',
            'signature': self._signature(
                'ABXA1IsyTalTXIojxmGnIUGyZASmvqEvTQ98jJ5KFs2FTswLEmsoqFX'
                'fU6l5_fous-tsbXOfLN-7PjfZ5XWPvg'),
        })
        self._validate(msg)

    def test_status_request(self):
        from letsencrypt.client.acme import status_request
        msg = status_request(u'O7-s9MNq1siZHlgrMzi9_A')
        self.assertEqual(msg, {
            'type': 'statusRequest',
            'token': u'O7-s9MNq1siZHlgrMzi9_A',
        })
        self._validate(msg)


if __name__ == '__main__':
    unittest.main()
