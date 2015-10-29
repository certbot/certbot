"""Test for letsencrypt_plesk.configurator."""
import unittest
import mock

from letsencrypt import errors
from letsencrypt_plesk import configurator
from letsencrypt_plesk.tests import api_mock
from acme import challenges


class PleskConfiguratorTest(unittest.TestCase):
    def setUp(self):
        super(PleskConfiguratorTest, self).setUp()
        self.configurator = configurator.PleskConfigurator(
            config=mock.MagicMock(),
            name="plesk"
        )
        self.configurator.plesk_api_client = api_mock.PleskApiMock()
        self.configurator.prepare()

    def test_get_all_names_none(self):
        self.configurator.plesk_api_client.expects_request(
            'request_site_get_all')
        self.configurator.plesk_api_client.will_response(
            'response_site_get_all_none')
        names = self.configurator.get_all_names()
        self.configurator.plesk_api_client.assert_called()
        self.assertEqual(names, [])

    def test_get_all_names_one(self):
        self.configurator.plesk_api_client.expects_request(
            'request_site_get_all')
        self.configurator.plesk_api_client.will_response(
            'response_site_get_all_one')
        names = self.configurator.get_all_names()
        self.configurator.plesk_api_client.assert_called()
        self.assertEqual(names, ['first.example.com', 'second.example.com'])

    def test_get_all_names_many(self):
        self.configurator.plesk_api_client.expects_request(
            'request_site_get_all')
        self.configurator.plesk_api_client.will_response(
            'response_site_get_all_many')
        names = self.configurator.get_all_names()
        self.configurator.plesk_api_client.assert_called()
        self.assertEqual(names, [
            'first.example.com', 'second.example.com', 'third.example.com',
            'fourth.example.com'])

    def test_supported_enhancements(self):
        self.assertEqual([], self.configurator.supported_enhancements())

    def test_enhance(self):
        self.assertRaises(errors.NotSupportedError, self.configurator.enhance,
                          'example.com', 'redirect')

    def test_view_config_changes(self):
        self.assertRaises(errors.NotSupportedError,
                          self.configurator.view_config_changes)

    def test_get_all_certs_keys(self):
        self.assertEqual([], self.configurator.get_all_certs_keys())

    def test_get_chall_pref(self):
        self.assertEqual([challenges.SimpleHTTP],
                         self.configurator.get_chall_pref('example.com'))

if __name__ == "__main__":
    unittest.main()  # pragma: no cover
