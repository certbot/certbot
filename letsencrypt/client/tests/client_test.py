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


class RollbackTest(unittest.TestCase):
    """Test the rollback function."""
    def setUp(self):
        from letsencrypt.client.plugins.apache.configurator import (
            ApacheConfigurator)
        self.m_install = mock.MagicMock(spec=ApacheConfigurator)

    @classmethod
    def _call(cls, checkpoints):
        from letsencrypt.client.client import rollback
        rollback(None, checkpoints, {}, mock.MagicMock())

    @mock.patch("letsencrypt.client.client.display_ops.pick_installer")
    def test_no_problems(self, mock_pick_installer):
        mock_pick_installer.side_effect = self.m_install

        self._call(1)

        self.assertEqual(self.m_install().rollback_checkpoints.call_count, 1)
        self.assertEqual(self.m_install().restart.call_count, 1)

    @mock.patch("letsencrypt.client.client.display_ops.pick_installer")
    def test_no_installer(self, mock_pick_installer):
        mock_pick_installer.return_value = None
        self._call(1)
        # Just make sure no exceptions are raised


if __name__ == "__main__":
    unittest.main()
