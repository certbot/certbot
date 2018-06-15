"""Tests for new style enhancements"""
import unittest
import mock

from certbot import updater

from certbot.plugins import enhancements

import certbot.tests.util as test_util


class EnhancementTest(test_util.ConfigTestCase):
    """Tests for new style enhancements in certbot.plugins.enhancements"""

    def setUp(self):
        super(EnhancementTest, self).setUp()
        self.mockinstaller = test_util.MockInstallerAutoHSTS()

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

    @test_util.patch_get_utility()
    def test_enhancement_enabled_enhancements(self, _):
        FAKEINDEX = [
            {
                "name": "autohsts",
                "cli_dest": "auto_hsts",
            },
            {
                "name": "somethingelse",
                "cli_dest": "something",
            }
        ]
        with mock.patch("certbot.plugins.enhancements._INDEX", FAKEINDEX):
            self.config.auto_hsts = True
            self.config.something = True
            enabled = list(enhancements.enabled_enhancements(self.config))
        self.assertEqual(len(enabled), 2)
        self.assertTrue([i for i in enabled if i["name"] == "autohsts"])
        self.assertTrue([i for i in enabled if i["name"] == "somethingelse"])


if __name__ == '__main__':
    unittest.main()  # pragma: no cover
