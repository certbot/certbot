"""Test for certbot_dovecot.configurator."""
import unittest
import mock
import os
import subprocess
import shutil
import tempfile

from certbot import errors
from certbot.tests import util as certbot_test_util

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

    @mock.patch("certbot_dovecot.configurator.util.exe_exists")
    def test_prepare_no_install(self, mock_exe_exists):
        mock_exe_exists.return_value = False
        self.assertRaises(
            errors.NoInstallationError, self.config.prepare)

    def test_prepare(self):
        self.assertEqual((2, 2, 25), self.config.version)

    @mock.patch("certbot_dovecot.configurator.util.exe_exists")
    @mock.patch("certbot_dovecot.configurator.subprocess.Popen")
    def test_prepare_initializes_version(self, mock_popen, mock_exe_exists):
        mock_popen().communicate.return_value = (
            "", "\n".join(["2.2.27 (c0f36b0)"]))

        mock_exe_exists.return_value = True

        self.config.version = None
        self.config.config_test = mock.Mock()
        self.config.prepare()
        self.assertEqual((2, 2, 27), self.config.version)

    def test_prepare_locked(self):
        server_root = self.config.conf("server-root")
        self.config.config_test = mock.Mock()
        os.remove(os.path.join(server_root, ".certbot.lock"))
        certbot_test_util.lock_and_call(self._test_prepare_locked, server_root)

    @mock.patch("certbot_dovecot.configurator.util.exe_exists")
    def _test_prepare_locked(self, unused_exe_exists):
        try:
            self.config.prepare()
        except errors.PluginError as err:
            err_msg = str(err)
            self.assertTrue("lock" in err_msg)
            self.assertTrue(self.config.conf("server-root") in err_msg)
        else:  # pragma: no cover
            self.fail("Exception wasn't raised!")

    def test_supported_enhancements(self):
        self.assertEqual([], self.config.supported_enhancements())

    def test_deploy_cert(self):
        self.config.deploy_cert(
            "www.example.com",
            "example/cert.pem",
            "example/key.pem",
            "example/chain.pem",
            "example/fullchain.pem")
        self.assertEquals(self._doveconf_get("ssl"), "yes")
        self.assertEquals(self._doveconf_get("ssl_cert"), "<example/fullchain.pem")
        self.assertEquals(self._doveconf_get("ssl_protocols"), "!SSLv3 !SSLv2")
        self.assertEquals(self._doveconf_get("ssl_dh_parameters_length"), "2048")

    def _doveconf_get(self, param):
        try:
            proc = subprocess.Popen(["doveconf", "-c", self.config.dovecot_conf, "-h", param],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True)
            return proc.communicate()[0].strip()
        except (OSError, ValueError):
            raise errors.MisconfigurationError("dovecot restart failed")

    @mock.patch("certbot_dovecot.configurator.subprocess.Popen")
    def test_dovecot_restart(self, mock_popen):
        mocked = mock_popen()
        mocked.communicate.return_value = ('', '')
        mocked.returncode = 0
        self.config.restart()

    @mock.patch("certbot_dovecot.configurator.subprocess.Popen")
    def test_no_dovecot_start(self, mock_popen):
        mock_popen.side_effect = OSError("Can't find program")
        self.assertRaises(errors.MisconfigurationError, self.config.restart)

    @mock.patch("certbot.util.run_script")
    def test_config_test_bad_process(self, mock_run_script):
        mock_run_script.side_effect = errors.SubprocessError
        self.assertRaises(errors.MisconfigurationError, self.config.config_test)

    @mock.patch("certbot.util.run_script")
    def test_config_test(self, _):
        self.config.config_test()


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
