"""Tests for certbot.renewal"""
import os
import mock
import unittest
import tempfile

from certbot import configuration
from certbot import storage

from certbot.tests import util


class RenewalTest(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.config_dir = os.path.join(self.tmp_dir, 'config')

    @mock.patch("certbot.cli.set_by_cli")
    def test_ancient_webroot_renewal_conf(self, mock_set_by_cli):
        mock_set_by_cli.return_value = False
        rc_path = util.make_lineage(self, 'sample-renewal-ancient.conf')
        args = mock.MagicMock(account=None, email=None, webroot_path=None)
        config = configuration.NamespaceConfig(args)
        lineage = storage.RenewableCert(
                rc_path, configuration.RenewerConfiguration(config))
        renewalparams = lineage.configuration["renewalparams"]
        # pylint: disable=protected-access
        from certbot import renewal
        renewal._restore_webroot_config(config, renewalparams)
        self.assertEqual(config.webroot_path, ["/var/www/"])
