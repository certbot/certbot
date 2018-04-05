"""Test for certbot_sendmail.configurator."""
import unittest
import mock
import os
import subprocess
import shutil
import tempfile

from certbot import errors
from certbot.tests import util as certbot_test_util

from certbot.plugins import common
from certbot_sendmail import configurator

class SendmailConfiguratorTest(unittest.TestCase):
    """Test a semi complex vhost configuration."""
    def setUp(self):
        super(SendmailConfiguratorTest, self).setUp()

    def test_prepare(self):
        config, _ = get_configurator()
        config.prepare()

    @certbot_test_util.patch_get_utility()
    def test_deploy(self, mock_getutility):
        mock_utility = mock_getutility()
        mock_utility.notification = mock.MagicMock(return_value=True)
        config, _ = get_configurator()
        config.prepare()
        config.deploy_cert("example.com", "path/cert123.pem", "path/ultrasecret123.pem",
            "path/one_chain.pem", "path/full_chain.pem")
        config.save()

    @certbot_test_util.patch_get_utility()
    def test_configure_empty(self, mock_getutility):
        mock_utility = mock_getutility()
        mock_utility.notification = mock.MagicMock(return_value=True)
        config, tempdir = get_configurator(tls_filename="nonexistant.m4", output_diff="output.diff")
        config.prepare()
        config.deploy_cert("example.com", "path/cert123.pem", "path/ultrasecret123.pem",
            "path/one_chain.pem", "path/full_chain.pem")
        config.save()
        with open(os.path.join(tempdir, "output.diff")) as f:
            actual = f.readlines()
        expected = [
            "--- \n", "+++ \n", "@@ -0,0 +1,6 @@\n",
            "+define(`confSERVER_CERT', `path/cert123.pem')dnl\n",
            "+define(`confCACERT_PATH', `path')dnl\n",
            "+define(`confSERVER_KEY', `path/ultrasecret123.pem')dnl\n",
            "+define(`confCACERT', `path/full_chain.pem')dnl\n",
            "+define(`confCLIENT_CERT', `path/cert123.pem')dnl\n",
            "+define(`confCLIENT_KEY', `path/ultrasecret123.pem')dnl\n",
        ]
        self.assertEqual(tuple(expected), tuple(actual))

def get_configurator(tls_filename="starttls.m4", write_tls_data=None, output_diff=None):
        tempdir, _, _ = common.dir_setup(
            "etc_mail", "certbot_sendmail.tests")
        backups = os.path.join(tempdir, "backups")
        config_path = os.path.join(tempdir, "etc_mail")
        if write_tls_data:
            tls_path = os.path.join(config_path, tls_filename)
            with open(tls_path, 'w') as f:
                f.write(write_tls_data)
        diff_file = None
        if output_diff:
            diff_file = os.path.join(tempdir, output_diff)
        return configurator.SendmailConfigurator(
            config=mock.MagicMock(
                    backup_dir=backups,
                    temp_checkpoint_dir=os.path.join(backups, "temp_checkpoints"),
                    in_progress_dir=os.path.join(backups, "IN_PROGRESS"),
                    sendmail_server_root=config_path,
                    sendmail_tls_config_file=tls_filename,
                    sendmail_diff_file=diff_file,
                ), name="sendmail"), tempdir


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
