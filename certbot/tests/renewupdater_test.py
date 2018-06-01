"""Tests for renewal updater interfaces"""
import unittest
import mock

from certbot import interfaces
from certbot import main
from certbot import updater

import certbot.tests.util as test_util


class RenewUpdaterTest(test_util.ConfigTestCase):
    """Tests for interfaces.RenewDeployer and interfaces.GenericUpdater"""

    def setUp(self):
        super(RenewUpdaterTest, self).setUp()
        class MockInstallerGenericUpdater(interfaces.GenericUpdater):
            """Mock class that implements GenericUpdater"""
            def __init__(self, *args, **kwargs):
                # pylint: disable=unused-argument
                self.restart = mock.MagicMock()
                self.callcounter = mock.MagicMock()
            def generic_updates(self, lineage, *args, **kwargs):
                self.callcounter(*args, **kwargs)

        class MockInstallerRenewDeployer(interfaces.RenewDeployer):
            """Mock class that implements RenewDeployer"""
            def __init__(self, *args, **kwargs):
                # pylint: disable=unused-argument
                self.callcounter = mock.MagicMock()
            def renew_deploy(self, lineage, *args, **kwargs):
                self.callcounter(*args, **kwargs)

        self.generic_updater = MockInstallerGenericUpdater()
        self.renew_deployer = MockInstallerRenewDeployer()

    @mock.patch('certbot.main._get_and_save_cert')
    @mock.patch('certbot.plugins.selection.choose_configurator_plugins')
    @test_util.patch_get_utility()
    def test_server_updates(self, _, mock_select, mock_getsave):
        mock_getsave.return_value = mock.MagicMock()
        mock_generic_updater = self.generic_updater

        # Generic Updater
        mock_select.return_value = (mock_generic_updater, None)
        with mock.patch('certbot.main._init_le_client'):
            main.renew_cert(self.config, None, mock.MagicMock())
        self.assertTrue(mock_generic_updater.restart.called)

        mock_generic_updater.restart.reset_mock()
        mock_generic_updater.callcounter.reset_mock()
        updater.run_generic_updaters(self.config, mock.MagicMock(), None)
        self.assertEqual(mock_generic_updater.callcounter.call_count, 1)
        self.assertFalse(mock_generic_updater.restart.called)

    def test_renew_deployer(self):
        lineage = mock.MagicMock()
        mock_deployer = self.renew_deployer
        updater.run_renewal_deployer(self.config, lineage, mock_deployer)
        self.assertTrue(mock_deployer.callcounter.called_with(lineage))

    @mock.patch("certbot.updater.logger.debug")
    def test_updater_skip_dry_run(self, mock_log):
        self.config.dry_run = True
        updater.run_generic_updaters(self.config, None, None)
        self.assertTrue(mock_log.called)
        self.assertEquals(mock_log.call_args[0][0],
                          "Skipping updaters in dry-run mode.")

    @mock.patch("certbot.updater.logger.debug")
    def test_deployer_skip_dry_run(self, mock_log):
        self.config.dry_run = True
        updater.run_renewal_deployer(self.config, None, None)
        self.assertTrue(mock_log.called)
        self.assertEquals(mock_log.call_args[0][0],
                          "Skipping renewal deployer in dry-run mode.")


if __name__ == '__main__':
    unittest.main()  # pragma: no cover
