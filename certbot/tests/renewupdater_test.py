"""Tests for renewal updater interfaces"""
import unittest
import mock

from certbot import errors
from certbot import interfaces
from certbot import main

from certbot.plugins import selection

import certbot.tests.util as test_util


class RenewUpdaterTest(unittest.TestCase):
    """Tests for interfaces.ServerTLSUpdater and
    interfaces.GenericUpdater"""

    def setUp(self):
        class MockInstallerTLSUpdater(interfaces.ServerTLSUpdater):
            """Mock class that implements ServerTLSUpdater"""
            def __init__(self, *args, **kwargs):
                # pylint: disable=unused-argument
                self.restart = mock.MagicMock()
                self.callcounter = mock.MagicMock()
            def server_tls_updates(self, domain, *args, **kwargs):
                self.callcounter(*args, **kwargs)

        class MockInstallerGenericUpdater(interfaces.GenericUpdater):
            """Mock class that implements GenericUpdater"""
            def __init__(self, *args, **kwargs):
                # pylint: disable=unused-argument
                self.restart = mock.MagicMock()
                self.callcounter = mock.MagicMock()
            def generic_updates(self, domain, *args, **kwargs):
                self.callcounter(*args, **kwargs)

        class MockInstallerRenewDeployer(interfaces.RenewDeployer):
            """Mock class that implements RenewDeployer"""
            def __init__(self, *args, **kwargs):
                # pylint: disable=unused-argument
                self.callcounter = mock.MagicMock()
            def renew_deploy(self, lineage, *args, **kwargs):
                self.callcounter(*args, **kwargs)

        self.tls_installer = MockInstallerTLSUpdater()
        self.generic_updater = MockInstallerGenericUpdater()
        self.renew_deployer = MockInstallerRenewDeployer()

    def get_config(self, args):
        """Get mock config from dict of parameters"""
        config = mock.MagicMock()
        for key in args.keys():
            config.__dict__[key] = args[key]
        return config

    @mock.patch('certbot.plugins.selection.z_util')
    def test_verify_enhancements_tlsupdater(self, mock_z):
        mock_z().yesno.return_value = False
        config = self.get_config({"server_tls_updates": False})
        self.assertRaises(errors.Error,
                          selection.verify_enhancements_supported,
                          config, self.tls_installer)
        # No exception should be thrown
        mock_z().yesno.return_value = True
        selection.verify_enhancements_supported(config, self.tls_installer)

        # Plugin does not implement ServerTLSUpdater
        self.assertRaises(errors.PluginSelectionError,
                          selection.verify_enhancements_supported,
                          config, self.generic_updater)


    @mock.patch('certbot.main._get_and_save_cert')
    @mock.patch('certbot.plugins.selection.choose_configurator_plugins')
    @test_util.patch_get_utility()
    def test_server_updates(self, _, mock_select, mock_getsave):
        config = self.get_config({"server_tls_updates": True,
                                  "installer_updates": True})

        lineage = mock.MagicMock()
        lineage.names.return_value = ['firstdomain', 'seconddomain']
        mock_getsave.return_value = lineage
        mock_tls_installer = self.tls_installer
        mock_generic_updater = self.generic_updater

        # TLS Updater
        mock_select.return_value = (mock_tls_installer, None)
        with mock.patch('certbot.main._init_le_client'):
            main.renew_cert(config, None, mock.MagicMock())
        #self.assertEqual(mock_tls_installer.callcounter.call_count, 2)
        self.assertTrue(mock_tls_installer.restart.called)

        mock_tls_installer.restart.reset_mock()
        mock_tls_installer.callcounter.reset_mock()
        mock_tls_installer.renewed = []

        main.run_renewal_updaters(config, None, lineage)
        #self.assertEqual(mock_tls_installer.callcounter.call_count, 2)
        self.assertFalse(mock_tls_installer.restart.called)

        # Generic Updater
        mock_select.return_value = (mock_generic_updater, None)
        with mock.patch('certbot.main._init_le_client'):
            main.renew_cert(config, None, mock.MagicMock())
        #self.assertEqual(mock_generic_updater.callcounter.call_count, 2)
        self.assertTrue(mock_generic_updater.restart.called)

        mock_generic_updater.restart.reset_mock()
        mock_generic_updater.callcounter.reset_mock()
        mock_generic_updater.renewed = []

        main.run_renewal_updaters(config, None, lineage)
        self.assertEqual(mock_generic_updater.callcounter.call_count, 2)
        self.assertFalse(mock_generic_updater.restart.called)
        self.assertFalse(any(mock_generic_updater.renewed))

    def test_renew_deployer(self):
        config = self.get_config({"installer_updates": True})
        lineage = mock.MagicMock()
        lineage.names.return_value = ['firstdomain', 'seconddomain']
        mock_deployer = self.renew_deployer
        main._run_renewal_deployer(lineage, mock_deployer, config)
        self.assertTrue(mock_deployer.callcounter.called_with(lineage))


if __name__ == '__main__':
    unittest.main()  # pragma: no cover
