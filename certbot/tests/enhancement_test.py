"""Tests for new style enhancements"""
import unittest
import mock

from certbot import cli
from certbot import configuration
from certbot import errors
from certbot import main
from certbot import updater

from certbot.plugins import disco
from certbot.plugins import enhancements
from certbot.plugins import null

import certbot.tests.util as test_util


class EnhancementTest(test_util.ConfigTestCase):
    """Tests for new style enhancements in certbot.plugins.enhancements"""

    def setUp(self):
        super(EnhancementTest, self).setUp()
        class MockInstallerAutoHSTS(enhancements.AutoHSTSEnhancement):
            """Mock class that implements AutoHSTSEnhancement"""
            def __init__(self, *args, **kwargs):
                super(MockInstallerAutoHSTS, self).__init__(*args, **kwargs)
                # pylint: disable=unused-argument
                self.enable_counter = mock.MagicMock()
                self.update_counter = mock.MagicMock()
                self.deploy_counter = mock.MagicMock()
                self.restart = mock.MagicMock()

            def update_autohsts(self, lineage, *args, **kwargs):
                """Mock updater method."""
                self.update_counter(lineage, *args, **kwargs)

            def deploy_autohsts(self, lineage, *args, **kwargs):
                """Mock deployer method."""
                self.deploy_counter(lineage, *args, **kwargs)

            def enable_autohsts(self, lineage, domains, *args, **kwargs):
                """Mock enable method."""
                self.enable_counter(lineage, domains, *args, **kwargs)

        self.mockinstaller = MockInstallerAutoHSTS()

    def _call(self, args):
        plugins = disco.PluginsRegistry.find_all()
        config = configuration.NamespaceConfig(
            cli.prepare_and_parse_args(plugins, args))

        with mock.patch('certbot.cert_manager.get_certnames') as mock_certs:
            mock_certs.return_value = ['example.com']
            with mock.patch('certbot.cert_manager.domains_for_certname') as mock_dom:
                mock_dom.return_value = ['example.com']
                with mock.patch('certbot.main._init_le_client') as mock_init:
                    mock_client = mock.MagicMock()
                    mock_client.config = config
                    mock_init.return_value = mock_client
                    main.enhance(config, plugins)
                    return mock_client # returns the client

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

    @mock.patch('certbot.cert_manager.lineage_for_certname')
    @mock.patch('certbot.main.display_ops.choose_values')
    @mock.patch('certbot.main.plug_sel.pick_installer')
    @mock.patch('certbot.main.plug_sel.record_chosen_plugins')
    @test_util.patch_get_utility()
    def test_enhancement_enable(self, _, _rec, mock_inst, mock_choose, mock_lineage):
        mock_inst.return_value = self.mockinstaller
        mock_choose.return_value = ["example.com", "another.tld"]
        mock_lineage.return_value = mock.MagicMock(chain_path="/tmp/nonexistent")
        self._call(['enhance', '--auto-hsts'])
        self.assertTrue(self.mockinstaller.enable_counter.called)
        self.assertEquals(self.mockinstaller.enable_counter.call_args[0][1],
                          ["example.com", "another.tld"])

    @mock.patch('certbot.cert_manager.lineage_for_certname')
    @mock.patch('certbot.main.display_ops.choose_values')
    @mock.patch('certbot.main.plug_sel.pick_installer')
    @mock.patch('certbot.main.plug_sel.record_chosen_plugins')
    @test_util.patch_get_utility()
    def test_enhancement_enable_not_supported(self, _, _rec, mock_inst, mock_choose, mock_lineage):
        mock_inst.return_value = null.Installer(self.config, "null")
        mock_choose.return_value = ["example.com", "another.tld"]
        mock_lineage.return_value = mock.MagicMock(chain_path="/tmp/nonexistent")
        self.assertRaises(
            errors.NotSupportedError,
            self._call, ['enhance', '--auto-hsts'])



if __name__ == '__main__':
    unittest.main()  # pragma: no cover
