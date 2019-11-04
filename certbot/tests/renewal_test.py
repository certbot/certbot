"""Tests for certbot.renewal"""
import unittest
import mock

from acme import challenges

from certbot import configuration
from certbot import errors
from certbot import storage

import certbot.tests.util as test_util


class RenewalTest(test_util.ConfigTestCase):
    @mock.patch('certbot.cli.set_by_cli')
    def test_ancient_webroot_renewal_conf(self, mock_set_by_cli):
        mock_set_by_cli.return_value = False
        rc_path = test_util.make_lineage(
            self.config.config_dir, 'sample-renewal-ancient.conf')
        self.config.account = None
        self.config.email = None
        self.config.webroot_path = None
        config = configuration.NamespaceConfig(self.config)
        lineage = storage.RenewableCert(rc_path, config)
        renewalparams = lineage.configuration['renewalparams']
        # pylint: disable=protected-access
        from certbot import renewal
        renewal._restore_webroot_config(config, renewalparams)
        self.assertEqual(config.webroot_path, ['/var/www/'])

    @mock.patch('certbot.renewal.cli.set_by_cli')
    def test_webroot_params_conservation(self, mock_set_by_cli):
        # For more details about why this test is important, see:
        # certbot.plugins.webroot_test::WebrootActionTest::test_webroot_map_partial_without_perform
        from certbot import renewal
        mock_set_by_cli.return_value = False

        renewalparams = {
            'webroot_map': {'test.example.com': '/var/www/test'},
            'webroot_path': ['/var/www/test', '/var/www/other'],
        }
        renewal._restore_webroot_config(self.config, renewalparams)  # pylint: disable=protected-access
        self.assertEqual(self.config.webroot_map, {'test.example.com': '/var/www/test'})
        self.assertEqual(self.config.webroot_path, ['/var/www/test', '/var/www/other'])

        renewalparams = {
            'webroot_map': {},
            'webroot_path': '/var/www/test',
        }
        renewal._restore_webroot_config(self.config, renewalparams)  # pylint: disable=protected-access
        self.assertEqual(self.config.webroot_map, {})
        self.assertEqual(self.config.webroot_path, ['/var/www/test'])


class RestoreRequiredConfigElementsTest(test_util.ConfigTestCase):
    """Tests for certbot.renewal.restore_required_config_elements."""
    @classmethod
    def _call(cls, *args, **kwargs):
        from certbot.renewal import restore_required_config_elements
        return restore_required_config_elements(*args, **kwargs)

    @mock.patch('certbot.renewal.cli.set_by_cli')
    def test_allow_subset_of_names_success(self, mock_set_by_cli):
        mock_set_by_cli.return_value = False
        self._call(self.config, {'allow_subset_of_names': 'True'})
        self.assertTrue(self.config.allow_subset_of_names is True)

    @mock.patch('certbot.renewal.cli.set_by_cli')
    def test_allow_subset_of_names_failure(self, mock_set_by_cli):
        mock_set_by_cli.return_value = False
        renewalparams = {'allow_subset_of_names': 'maybe'}
        self.assertRaises(
            errors.Error, self._call, self.config, renewalparams)

    @mock.patch('certbot.renewal.cli.set_by_cli')
    def test_pref_challs_list(self, mock_set_by_cli):
        mock_set_by_cli.return_value = False
        renewalparams = {'pref_challs': 'http-01, dns'.split(',')}
        self._call(self.config, renewalparams)
        expected = [challenges.HTTP01.typ, challenges.DNS01.typ]
        self.assertEqual(self.config.pref_challs, expected)

    @mock.patch('certbot.renewal.cli.set_by_cli')
    def test_pref_challs_str(self, mock_set_by_cli):
        mock_set_by_cli.return_value = False
        renewalparams = {'pref_challs': 'dns'}
        self._call(self.config, renewalparams)
        expected = [challenges.DNS01.typ]
        self.assertEqual(self.config.pref_challs, expected)

    @mock.patch('certbot.renewal.cli.set_by_cli')
    def test_pref_challs_failure(self, mock_set_by_cli):
        mock_set_by_cli.return_value = False
        renewalparams = {'pref_challs': 'finding-a-shrubbery'}
        self.assertRaises(errors.Error, self._call, self.config, renewalparams)

    @mock.patch('certbot.renewal.cli.set_by_cli')
    def test_must_staple_success(self, mock_set_by_cli):
        mock_set_by_cli.return_value = False
        self._call(self.config, {'must_staple': 'True'})
        self.assertTrue(self.config.must_staple is True)

    @mock.patch('certbot.renewal.cli.set_by_cli')
    def test_must_staple_failure(self, mock_set_by_cli):
        mock_set_by_cli.return_value = False
        renewalparams = {'must_staple': 'maybe'}
        self.assertRaises(
            errors.Error, self._call, self.config, renewalparams)


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
