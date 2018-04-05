"""Test for certbot_dovecot.configurator."""
import unittest
import mock
import os
import shutil
import tempfile

from certbot import errors
from certbot.plugins import common
from certbot_dovecot import configurator


class DovecotConfiguratorTest(unittest.TestCase):
    """Test a semi complex vhost configuration."""
    def setUp(self):
        super(DovecotConfiguratorTest, self).setUp()
        self.temp_dir, self.config_dir, self.work_dir = common.dir_setup(
            "etc_dovecot", "certbot_dovecot.tests")
        self.logs_dir = tempfile.mkdtemp('logs')
        self.config_path = os.path.join(self.temp_dir, "etc_dovecot")
        self.config = get_mock_configurator(self.config_path, self.config_dir, self.work_dir, self.logs_dir)

    def tearDown(self):
        shutil.rmtree(self.temp_dir)
        shutil.rmtree(self.config_dir)
        shutil.rmtree(self.work_dir)
        shutil.rmtree(self.logs_dir)

    @mock.patch("certbot_nginx.configurator.util.exe_exists")
    def test_prepare_no_install(self, mock_exe_exists):
        mock_exe_exists.return_value = False
        self.assertRaises(
            errors.NoInstallationError, self.config.prepare)

    def test_prepare(self):
        self.assertEqual((2, 2, 25), self.config.version)

    @mock.patch("certbot_nginx.configurator.util.exe_exists")
    @mock.patch("certbot_nginx.configurator.subprocess.Popen")
    def test_prepare_initializes_version(self, mock_popen, mock_exe_exists):
        mock_popen().communicate.return_value = (
            "", "\n".join(["2.2.27 (c0f36b0)"]))

        mock_exe_exists.return_value = True

        self.config.version = None
        self.config.config_test = mock.Mock()
        self.config.prepare()
        self.assertEqual((2, 2, 27), self.config.version)

def get_mock_configurator(config_path, config_dir, work_dir, logs_dir, version=(2, 2, 25)):
    backups = os.path.join(work_dir, "backups")
    with mock.patch("certbot_dovecot.configurator.DovecotConfigurator."
                    "config_test"):
        with mock.patch("certbot_dovecot.configurator.util."
                        "exe_exists") as mock_exe_exists:
            mock_exe_exists.return_value = True
            config = configurator.DovecotConfigurator(
                config=mock.MagicMock(
                    dovecot_server_root=config_path,
                    config_dir=config_dir,
                    work_dir=work_dir,
                    logs_dir=logs_dir,
                    backup_dir=backups,
                    temp_checkpoint_dir=os.path.join(work_dir, "temp_checkpoints"),
                    in_progress_dir=os.path.join(backups, "IN_PROGRESS"),
                ),
                name="dovecot",
                version=version)
            config.prepare()
    return config

if __name__ == "__main__":
    unittest.main()  # pragma: no cover
