"""Tests for renewal updater interfaces"""
import unittest
import mock

from certbot import main
from certbot import updater

from certbot.plugins import enhancements

import certbot.tests.util as test_util


class RenewUpdaterTest(test_util.ConfigTestCase):
    """Tests for interfaces.RenewDeployer and interfaces.GenericUpdater"""

    def setUp(self):
        super(RenewUpdaterTest, self).setUp()
        self.generic_updater = test_util.MockInstallerGenericUpdater()
        self.renew_deployer = test_util.MockInstallerRenewDeployer()
        self.mockinstaller = test_util.MockInstallerAutoHSTS()

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

    @mock.patch('certbot.plugins.selection.choose_configurator_plugins')
    @test_util.patch_get_utility()
    def test_enhancement_updates(self, _, mock_select):
        mock_select.return_value = (self.mockinstaller, None)
        updater.run_generic_updaters(self.config, mock.MagicMock(), None)
        self.assertTrue(self.mockinstaller.update_counter.called)
        self.assertEqual(self.mockinstaller.update_counter.call_count, 1)

    @test_util.patch_get_utility()
    def test_enhancement_deployer(self, _):
        updater.run_renewal_deployer(self.config, mock.MagicMock(),
                                     self.mockinstaller)
        self.assertTrue(self.mockinstaller.deploy_counter.called)

    @mock.patch('certbot.plugins.selection.choose_configurator_plugins')
    @test_util.patch_get_utility()
    def test_enhancement_updates_not_called(self, _, mock_select):
        self.config.disable_renew_updates = True
        mock_select.return_value = (self.mockinstaller, None)
        updater.run_generic_updaters(self.config, mock.MagicMock(), None)
        self.assertFalse(self.mockinstaller.update_counter.called)

    @test_util.patch_get_utility()
    def test_enhancement_deployer_not_called(self, _):
        self.config.disable_renew_updates = True
        updater.run_renewal_deployer(self.config, mock.MagicMock(),
                                     self.mockinstaller)
        self.assertFalse(self.mockinstaller.deploy_counter.called)

    @mock.patch('certbot.plugins.selection.choose_configurator_plugins')
    @test_util.patch_get_utility()
    def test_enhancement_no_updater(self, _, mock_select):
        FAKEINDEX = [
            {
                "name": "Test",
                "class": enhancements.AutoHSTSEnhancement,
                "updater_function": None,
                "deployer_function": "deploy_autohsts",
                "enable_function": "enable_autohsts"
            }
        ]
        mock_select.return_value = (self.mockinstaller, None)
        with mock.patch("certbot.plugins.enhancements._INDEX", FAKEINDEX):
            updater.run_generic_updaters(self.config, mock.MagicMock(), None)
        self.assertFalse(self.mockinstaller.update_counter.called)

    @test_util.patch_get_utility()
    def test_enhancement_no_deployer(self, _):
        FAKEINDEX = [
            {
                "name": "Test",
                "class": enhancements.AutoHSTSEnhancement,
                "updater_function": "deploy_autohsts",
                "deployer_function": None,
                "enable_function": "enable_autohsts"
            }
        ]
        with mock.patch("certbot.plugins.enhancements._INDEX", FAKEINDEX):
            updater.run_renewal_deployer(self.config, mock.MagicMock(),
                                         self.mockinstaller)
        self.assertFalse(self.mockinstaller.deploy_counter.called)


if __name__ == '__main__':
    unittest.main()  # pragma: no cover
