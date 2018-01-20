"""Test for certbot_installer_zimbra.installer."""
import os
import tempfile
import unittest

import mock
import zope.component

from certbot import configuration
from certbot import errors
from certbot.plugins import common

from certbot_installer_zimbra.installer import ZimbraInstaller

class ZimbraInstallerTest(unittest.TestCase):

    def setUp(self):
        self.temp_dir, self.config_dir, self.work_dir = common.dir_setup('opt_zimbra', 'certbot_installer_zimbra')
        self.logs_dir = tempfile.mkdtemp('logs')
        backups = os.path.join(self.work_dir, "backups")

        self.zimbra_root = self.temp_dir

        with mock.patch("certbot_installer_zimbra.installer.util.exe_exists") as mock_exe_exists:
            with mock.patch('certbot_installer_zimbra.installer.pwd.getpwnam') as mock_getpwnam:
                with mock.patch('certbot_installer_zimbra.installer.util.lock_dir_until_exit') as mock_lock_dir_until_exit:
                    with mock.patch('certbot_installer_zimbra.installer.ZimbraInstaller._exec_zimbra') as mock_exec_zimbra:
                        mock_lock_dir_until_exit.return_value = True
                        mock_exe_exists.return_value = True
                        mock_getpwnam.return_value = mock.MagicMock(
                            pw_name = 'zimbra',
                            pw_uid = 999,
                            pw_gid = 999,
                            pw_dir = self.zimbra_root
                        )

                        self.installer = ZimbraInstaller(
                            config=mock.MagicMock(
                                zimbra_zimbra_root = self.zimbra_root,
                                config_dir=self.config_dir,
                                work_dir=self.work_dir,
                                logs_dir=self.logs_dir,
                                backup_dir=backups,
                                temp_checkpoint_dir=os.path.join(self.work_dir, "temp_checkpoints"),
                                in_progress_dir=os.path.join(backups, "IN_PROGRESS")
                            ),
                            name="zimbra")
                        self.installer.prepare()

                        nsconfig = configuration.NamespaceConfig(self.installer.config)
                        zope.component.provideUtility(nsconfig)

    @mock.patch("certbot_installer_zimbra.installer.util.exe_exists")
    def test_prepare_not_install(self, mock_exe_exists):
        mock_exe_exists.return_value = False
        self.assertRaises(
            errors.NoInstallationError, self.installer.prepare)

    @mock.patch("certbot_installer_zimbra.installer.pwd.getpwnam")
    def test_prepare_user_not_exist(self, mock_getpwnam):
        mock_getpwnam.side_effect = KeyError()
        self.assertRaises(
            errors.NoInstallationError, self.installer.prepare)

    def test_prepare(self):
        self.assertEquals(os.path.join(self.zimbra_root, 'certbot-tmp'), self.installer.zimbra_temp_path)
        self.assertEquals(os.path.join(self.zimbra_root, 'ssl/zimbra/commercial'), self.installer.zimbra_cert_path)

