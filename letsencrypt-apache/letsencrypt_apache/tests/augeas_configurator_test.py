"""Test for letsencrypt_apache.augeas_configurator."""
import os
import shutil
import unittest

import mock

from letsencrypt import errors

from letsencrypt.tests import acme_util

from letsencrypt_apache import configurator
from letsencrypt_apache import obj

from letsencrypt_apache.tests import util


class AugeasConfiguratorTest(util.ApacheTest):
    """Test for Augeas Configurator base class."""

    def setUp(self):  # pylint: disable=arguments-differ
        super(AugeasConfiguratorTest, self).setUp()

        self.config = util.get_apache_configurator(
            self.config_path, self.config_dir, self.work_dir)

        self.vh_truth = util.get_vh_truth(
            self.temp_dir, "debian_apache_2_4/two_vhost_80")

    def tearDown(self):
        shutil.rmtree(self.temp_dir)
        shutil.rmtree(self.config_dir)
        shutil.rmtree(self.work_dir)

    def test_bad_parse(self):
        self.config.parser._parse_file(os.path.join(
            self.config.parser.root, "conf-available", "bad_conf_file.conf"))
        self.assertRaises(
            errors.PluginError, self.config.check_parsing_errors, "httpd.aug")

    def test_bad_save(self):
        mock_save = mock.Mock()
        mock_save.side_effect = IOError
        self.config.aug.save = mock_save

        self.assertRaises(errors.PluginError, self.config.save)

    def test_finalize_save(self):
        mock_finalize = mock.Mock()
        self.config.reverter = mock_finalize
        self.config.save("Example Title")

        self.assertTrue(mock_finalize.is_called)

    def test_recovery_routine(self):
        mock_load = mock.Mock()
        self.config.aug.load = mock_load

        self.config.recovery_routine()
        self.assertEqual(mock_load.call_count, 1)

    def test_revert_challenge_config(self):
        mock_load = mock.Mock()
        self.config.aug.load = mock_load

        self.config.revert_challenge_config()
        self.assertEqual(mock_load.call_count, 1)

    def test_rollback_checkpoints(self):
        mock_load = mock.Mock()
        self.config.aug.load = mock_load

        self.config.rollback_checkpoints()
        self.assertEqual(mock_load.call_count, 1)

    def test_view_config_changes(self):
        self.config.view_config_changes()


if __name__ == "__main__":
    unittest.main()  # pragma: no cover