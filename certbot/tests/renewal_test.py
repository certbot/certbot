"""Tests for certbot.renewal"""
import os
import mock
import unittest
import tempfile

from certbot import configuration
from certbot import errors
from certbot import storage

from certbot.tests import util


class RenewalTest(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.config_dir = os.path.join(self.tmp_dir, 'config')

    @mock.patch('certbot.cli.set_by_cli')
    def test_ancient_webroot_renewal_conf(self, mock_set_by_cli):
        mock_set_by_cli.return_value = False
        rc_path = util.make_lineage(self, 'sample-renewal-ancient.conf')
        args = mock.MagicMock(account=None, email=None, webroot_path=None)
        config = configuration.NamespaceConfig(args)
        lineage = storage.RenewableCert(rc_path, config)
        renewalparams = lineage.configuration['renewalparams']
        # pylint: disable=protected-access
        from certbot import renewal
        renewal._restore_webroot_config(config, renewalparams)
        self.assertEqual(config.webroot_path, ['/var/www/'])


class RestoreRequiredConfigElementsTest(unittest.TestCase):
    """Tests for certbot.renewal.restore_required_config_elements."""
    def setUp(self):
        self.config = mock.MagicMock()

    @classmethod
    def _call(cls, *args, **kwargs):
        from certbot.renewal import restore_required_config_elements
        return restore_required_config_elements(*args, **kwargs)

    @mock.patch('certbot.renewal.cli.set_by_cli')
    def test_allow_subset_of_names_success(self, mock_set_by_cli):
        mock_set_by_cli.return_value = False
        self._call(self.config, {'allow_subset_of_names': 'True'})
        self.assertTrue(self.config.namespace.allow_subset_of_names is True)

    @mock.patch('certbot.renewal.cli.set_by_cli')
    def test_allow_subset_of_names_failure(self, mock_set_by_cli):
        mock_set_by_cli.return_value = False
        renewalparams = {'allow_subset_of_names': 'maybe'}
        self.assertRaises(
            errors.Error, self._call, self.config, renewalparams)

    @mock.patch('certbot.renewal.cli.set_by_cli')
    def test_must_staple_success(self, mock_set_by_cli):
        mock_set_by_cli.return_value = False
        self._call(self.config, {'must_staple': 'True'})
        self.assertTrue(self.config.namespace.must_staple is True)

    @mock.patch('certbot.renewal.cli.set_by_cli')
    def test_must_staple_failure(self, mock_set_by_cli):
        mock_set_by_cli.return_value = False
        renewalparams = {'must_staple': 'maybe'}
        self.assertRaises(
            errors.Error, self._call, self.config, renewalparams)

if __name__ == "__main__":
    unittest.main()  # pragma: no cover
