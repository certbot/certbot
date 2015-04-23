"""letsencrypt.client.client.py tests."""
import os
import unittest
import shutil
import tempfile

import mock

from letsencrypt.client import account
from letsencrypt.client import configuration
from letsencrypt.client import errors
from letsencrypt.client import le_util


class DetermineAccountTest(unittest.TestCase):
    def setUp(self):
        self.accounts_dir = tempfile.mkdtemp("accounts")
        account_keys_dir = os.path.join(self.accounts_dir, "keys")
        os.makedirs(account_keys_dir, 0o700)

        self.config = mock.MagicMock(
            spec=configuration.NamespaceConfig, accounts_dir=self.accounts_dir,
            account_keys_dir=account_keys_dir, rsa_key_size=2048,
            server="letsencrypt-demo.org")

    def tearDown(self):
        shutil.rmtree(self.accounts_dir)

    @mock.patch("letsencrypt.client.client.account.Account.from_prompts")
    @mock.patch("letsencrypt.client.client.display_ops.choose_account")
    def determine_account(self, mock_op, mock_prompt):
        """Test determine account"""
        from letsencrypt.client import client

        key = le_util.Key("file", "pem")
        test_acc = account.Account(self.config, key, "email1@gmail.com")
        mock_op.return_value = test_acc

        # Test 0
        mock_prompt.return_value = None
        self.assertTrue(client.determine_account(self.config) is None)

        # Test 1
        test_acc.save()
        acc = client.determine_account(self.config)
        self.assertEqual(acc.email, test_acc.email)

        # Test multiple
        self.assertFalse(mock_op.called)
        acc2 = account.Account(self.config, key)
        acc2.save()
        chosen_acc = client.determine_account(self.config)
        self.assertTrue(mock_op.called)
        self.assertTrue(chosen_acc.email, test_acc.email)


class DetermineAuthenticatorTest(unittest.TestCase):
    def setUp(self):
        from letsencrypt.client.plugins.apache.configurator import (
            ApacheConfigurator)
        from letsencrypt.client.plugins.standalone.authenticator import (
            StandaloneAuthenticator)

        self.mock_stand = mock.MagicMock(
            spec=StandaloneAuthenticator, description="Apache Web Server")
        self.mock_apache = mock.MagicMock(
            spec=ApacheConfigurator, description="Standalone Authenticator")

        self.mock_config = mock.MagicMock(
            spec=configuration.NamespaceConfig, authenticator=None)

        self.all_auths = {
            'apache': self.mock_apache,
            'standalone': self.mock_stand
        }

    @classmethod
    def _call(cls, all_auths, config):
        from letsencrypt.client.client import determine_authenticator
        return determine_authenticator(all_auths, config)

    @mock.patch("letsencrypt.client.client.display_ops.choose_authenticator")
    def test_accept_two(self, mock_choose):
        mock_choose.return_value = self.mock_stand()
        self.assertEqual(self._call(self.all_auths, self.mock_config),
                         self.mock_stand())

    def test_accept_one(self):
        self.mock_apache.prepare.return_value = self.mock_apache
        one_avail_auth = {
            'apache': self.mock_apache
        }
        self.assertEqual(self._call(one_avail_auth, self.mock_config),
                         self.mock_apache)

    def test_no_installation_one(self):
        self.mock_apache.prepare.side_effect = (
            errors.LetsEncryptNoInstallationError)

        self.assertEqual(self._call(self.all_auths, self.mock_config),
                         self.mock_stand)

    def test_no_installations(self):
        self.mock_apache.prepare.side_effect = (
            errors.LetsEncryptNoInstallationError)
        self.mock_stand.prepare.side_effect = (
            errors.LetsEncryptNoInstallationError)

        self.assertRaises(errors.LetsEncryptClientError,
                          self._call,
                          self.all_auths,
                          self.mock_config)

    @mock.patch("letsencrypt.client.client.logging")
    @mock.patch("letsencrypt.client.client.display_ops.choose_authenticator")
    def test_misconfigured(self, mock_choose, unused_log):
        self.mock_apache.prepare.side_effect = (
            errors.LetsEncryptMisconfigurationError)
        mock_choose.return_value = self.mock_apache

        self.assertTrue(self._call(self.all_auths, self.mock_config) is None)

    def test_choose_valid_auth_from_cmd_line(self):
        standalone_config = mock.MagicMock(spec=configuration.NamespaceConfig,
                                           authenticator='standalone')
        self.assertEqual(self._call(self.all_auths, standalone_config),
                         self.mock_stand)

        apache_config = mock.MagicMock(spec=configuration.NamespaceConfig,
                                       authenticator='apache')
        self.assertEqual(self._call(self.all_auths, apache_config),
                         self.mock_apache)

    def test_choose_invalid_auth_from_cmd_line(self):
        invalid_config = mock.MagicMock(spec=configuration.NamespaceConfig,
                                        authenticator='foobar')
        self.assertRaises(errors.LetsEncryptClientError,
                          self._call,
                          self.all_auths,
                          invalid_config)


class RollbackTest(unittest.TestCase):
    """Test the rollback function."""
    def setUp(self):
        from letsencrypt.client.plugins.apache.configurator import (
            ApacheConfigurator)
        self.m_install = mock.MagicMock(spec=ApacheConfigurator)

    @classmethod
    def _call(cls, checkpoints):
        from letsencrypt.client.client import rollback
        rollback(checkpoints, mock.MagicMock())

    @mock.patch("letsencrypt.client.client.determine_installer")
    def test_no_problems(self, mock_det):
        mock_det.side_effect = self.m_install

        self._call(1)

        self.assertEqual(self.m_install().rollback_checkpoints.call_count, 1)
        self.assertEqual(self.m_install().restart.call_count, 1)

    @mock.patch("letsencrypt.client.client.determine_installer")
    def test_no_installer(self, mock_det):
        mock_det.return_value = None

        # Just make sure no exceptions are raised
        self._call(1)


if __name__ == "__main__":
    unittest.main()
