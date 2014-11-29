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

class ChallengeRequestTest(unittest.TestCase):
    """Tests for letsencrypt.client.acme.challenge_request_test"""

    def test_parameter_becomes_result(self):
        """Test parameter is passed to result object unchanged"""
        from letsencrypt.client.acme import challenge_request
        self.assertEqual(
            challenge_request("domainname"),
            {
                "type": "challengeRequest",
                "identifier": "domainname",
            }
        )

    def test_supports_unicode(self):
        """Test support unicode parameter"""
        from letsencrypt.client.acme import challenge_request
        self.assertEqual(
            challenge_request(u'unicode'),
            {
                "type": "challengeRequest",
                "identifier": u'unicode',
            }
        )

if __name__ == '__main__':
    unittest.main()
