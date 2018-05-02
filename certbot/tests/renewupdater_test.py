"""Tests for renewal updater interfaces"""
import unittest
import mock

from certbot import interfaces
from certbot import main
from certbot import updater

import certbot.tests.util as test_util


class RenewUpdaterTest(unittest.TestCase):
    """Tests for interfaces.RenewDeployer and interfaces.GenericUpdater"""

    def setUp(self):
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

        self.generic_updater = MockInstallerGenericUpdater()
        self.renew_deployer = MockInstallerRenewDeployer()

    def get_config(self, args):
        """Get mock config from dict of parameters"""
        config = mock.MagicMock()
        for key in args.keys():
            config.__dict__[key] = args[key]
        return config

    @mock.patch('certbot.main._get_and_save_cert')
    @mock.patch('certbot.plugins.selection.choose_configurator_plugins')
    @test_util.patch_get_utility()
    def test_server_updates(self, _, mock_select, mock_getsave):
        config = self.get_config({"disable_renew_updates": False})

        lineage = mock.MagicMock()
        lineage.names.return_value = ['firstdomain', 'seconddomain']
        mock_getsave.return_value = lineage
        mock_generic_updater = self.generic_updater

        # Generic Updater
        mock_select.return_value = (mock_generic_updater, None)
        with mock.patch('certbot.main._init_le_client'):
            main.renew_cert(config, None, mock.MagicMock())
        self.assertTrue(mock_generic_updater.restart.called)

        mock_generic_updater.restart.reset_mock()
        mock_generic_updater.callcounter.reset_mock()
        updater.run_generic_updaters(config, None, lineage)
        self.assertEqual(mock_generic_updater.callcounter.call_count, 2)
        self.assertFalse(mock_generic_updater.restart.called)

    def test_renew_deployer(self):
        config = self.get_config({"disable_renew_updates": False})
        lineage = mock.MagicMock()
        lineage.names.return_value = ['firstdomain', 'seconddomain']
        mock_deployer = self.renew_deployer
        updater.run_renewal_deployer(lineage, mock_deployer, config)
        self.assertTrue(mock_deployer.callcounter.called_with(lineage))


if __name__ == '__main__':
    unittest.main()  # pragma: no cover
