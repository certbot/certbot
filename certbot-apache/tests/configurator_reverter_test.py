"""Test for certbot_apache._internal.configurator implementations of reverter"""
import shutil
import unittest

try:
    import mock
except ImportError: # pragma: no cover
    from unittest import mock # type: ignore

from certbot import errors
import util


class ConfiguratorReverterTest(util.ApacheTest):
    """Test for ApacheConfigurator reverter methods"""


    def setUp(self):  # pylint: disable=arguments-differ
        super().setUp()

        self.config = util.get_apache_configurator(
            self.config_path, self.vhost_path, self.config_dir, self.work_dir)

        self.vh_truth = util.get_vh_truth(
            self.temp_dir, "debian_apache_2_4/multiple_vhosts")

    def tearDown(self):
        shutil.rmtree(self.config_dir)
        shutil.rmtree(self.work_dir)
        shutil.rmtree(self.temp_dir)

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

        self.assertIs(mock_finalize.is_called, True)

    def test_revert_challenge_config(self):
        mock_load = mock.Mock()
        self.config.parser.aug.load = mock_load

        self.config.revert_challenge_config()
        self.assertEqual(mock_load.call_count, 1)

    def test_revert_challenge_config_error(self):
        self.config.reverter.revert_temporary_config = mock.Mock(
            side_effect=errors.ReverterError)

        self.assertRaises(
            errors.PluginError, self.config.revert_challenge_config)

    def test_rollback_checkpoints(self):
        mock_load = mock.Mock()
        self.config.parser.aug.load = mock_load

        self.config.rollback_checkpoints()
        self.assertEqual(mock_load.call_count, 1)

    def test_rollback_error(self):
        self.config.reverter.rollback_checkpoints = mock.Mock(
            side_effect=errors.ReverterError)
        self.assertRaises(errors.PluginError, self.config.rollback_checkpoints)

    def test_recovery_routine_reload(self):
        mock_load = mock.Mock()
        self.config.parser.aug.load = mock_load
        self.config.recovery_routine()
        self.assertEqual(mock_load.call_count, 1)


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
