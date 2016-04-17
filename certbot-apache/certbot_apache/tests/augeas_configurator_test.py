"""Test for certbot_apache.augeas_configurator."""
import os
import shutil
import unittest

import mock

from certbot import errors

from certbot_apache.tests import util


class AugeasConfiguratorTest(util.ApacheTest):
    """Test for Augeas Configurator base class."""

    def setUp(self):  # pylint: disable=arguments-differ
        super(AugeasConfiguratorTest, self).setUp()

        self.config = util.get_apache_configurator(
            self.config_path, self.vhost_path, self.config_dir, self.work_dir)

        self.vh_truth = util.get_vh_truth(
            self.temp_dir, "debian_apache_2_4/multiple_vhosts")

    def tearDown(self):
        shutil.rmtree(self.config_dir)
        shutil.rmtree(self.work_dir)
        shutil.rmtree(self.temp_dir)

    def test_bad_parse(self):
        # pylint: disable=protected-access
        self.config.parser._parse_file(os.path.join(
            self.config.parser.root, "conf-available", "bad_conf_file.conf"))
        self.assertRaises(
            errors.PluginError, self.config.check_parsing_errors, "httpd.aug")

    def test_bad_save(self):
        mock_save = mock.Mock()
        mock_save.side_effect = IOError
        self.config.aug.save = mock_save

        self.assertRaises(errors.PluginError, self.config.save)

    def test_bad_save_checkpoint(self):
        self.config.reverter.add_to_checkpoint = mock.Mock(
            side_effect=errors.ReverterError)
        self.config.parser.add_dir(
            self.vh_truth[0].path, "Test", "bad_save_ckpt")
        self.assertRaises(errors.PluginError, self.config.save)

    def test_bad_save_finalize_checkpoint(self):
        self.config.reverter.finalize_checkpoint = mock.Mock(
            side_effect=errors.ReverterError)
        self.config.parser.add_dir(
            self.vh_truth[0].path, "Test", "bad_save_ckpt")
        self.assertRaises(errors.PluginError, self.config.save, "Title")

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

    def test_recovery_routine_error(self):
        self.config.reverter.recovery_routine = mock.Mock(
            side_effect=errors.ReverterError)

        self.assertRaises(
            errors.PluginError, self.config.recovery_routine)

    def test_revert_challenge_config(self):
        mock_load = mock.Mock()
        self.config.aug.load = mock_load

        self.config.revert_challenge_config()
        self.assertEqual(mock_load.call_count, 1)

    def test_revert_challenge_config_error(self):
        self.config.reverter.revert_temporary_config = mock.Mock(
            side_effect=errors.ReverterError)

        self.assertRaises(
            errors.PluginError, self.config.revert_challenge_config)

    def test_rollback_checkpoints(self):
        mock_load = mock.Mock()
        self.config.aug.load = mock_load

        self.config.rollback_checkpoints()
        self.assertEqual(mock_load.call_count, 1)

    def test_rollback_error(self):
        self.config.reverter.rollback_checkpoints = mock.Mock(
            side_effect=errors.ReverterError)
        self.assertRaises(errors.PluginError, self.config.rollback_checkpoints)

    def test_view_config_changes(self):
        self.config.view_config_changes()

    def test_view_config_changes_error(self):
        self.config.reverter.view_config_changes = mock.Mock(
            side_effect=errors.ReverterError)
        self.assertRaises(errors.PluginError, self.config.view_config_changes)


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
