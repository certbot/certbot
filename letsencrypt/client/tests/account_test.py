import mock
import os
import pkg_resources
import shutil
import sys
import tempfile
import unittest

import zope.component

from letsencrypt.acme import messages2

from letsencrypt.client import account
from letsencrypt.client import configuration
from letsencrypt.client import le_util

from letsencrypt.client.display import util as display_util


class AccountTest(unittest.TestCase):
    """Tests letsencrypt.client.account.Account."""

    def setUp(self):
        self.accounts_dir = tempfile.mkdtemp("accounts")
        self.account_keys_dir = os.path.join(self.accounts_dir, "keys")
        os.makedirs(self.account_keys_dir, 0o700)

        self.config = mock.MagicMock(
            spec=configuration.NamespaceConfig, accounts_dir=self.accounts_dir,
            account_keys_dir=self.account_keys_dir, rsa_key_size=2048,
            server="letsencrypt-demo.org")

        rsa256_file = pkg_resources.resource_filename(
            "letsencrypt.client.tests", "testdata/rsa256_key.pem")
        rsa256_pem = pkg_resources.resource_string(
            "letsencrypt.client.tests", "testdata/rsa256_key.pem")

        self.key = le_util.Key(rsa256_file, rsa256_pem)
        self.email = "client@letsencrypt.org"
        self.regr = messages2.RegistrationResource(
            uri="uri",
            new_authzr_uri="new_authzr_uri",
            terms_of_service="terms_of_service",
            body=messages2.Registration(
                recovery_token="recovery_token", agreement="agreement")
        )

        self.test_account = account.Account(
            self.config, self.key, self.email, None, self.regr)

    def tearDown(self):
        shutil.rmtree(self.accounts_dir)

    @mock.patch("letsencrypt.client.account.zope.component.getUtility")
    @mock.patch("letsencrypt.client.account.crypto_util.init_save_key")
    def test_prompts(self, mock_key, mock_util):
        displayer = display_util.FileDisplay(sys.stdout)
        zope.component.provideUtility(displayer)

        mock_util().input.return_value = (display_util.OK, self.email)

        mock_key.return_value = self.key
        acc = account.Account.from_prompts(self.config)

        self.assertEqual(acc.email, self.email)
        self.assertEqual(acc.key, self.key)
        self.assertEqual(acc.config, self.config)

    def test_save(self):
        self.test_account.save()
        self._read_out_config(self.email)

    def test_save_from_existing_account(self):
        self.test_account.save()
        acc = account.Account.from_existing_account(self.config, self.email)

        self.assertEqual(acc.key, self.test_account.key)
        self.assertEqual(acc.email, self.test_account.email)
        self.assertEqual(acc.phone, self.test_account.phone)
        self.assertEqual(acc.regr, self.test_account.regr)

    def test_properties(self):
        self.assertEqual(self.test_account.uri, "uri")
        self.assertEqual(self.test_account.new_authzr_uri, "new_authzr_uri")
        self.assertEqual(self.test_account.terms_of_service, "terms_of_service")
        self.assertEqual(self.test_account.recovery_token, "recovery_token")

    def test_partial_properties(self):
        partial = account.Account(self.config, self.key)

        self.assertTrue(partial.uri is None)
        self.assertTrue(partial.new_authzr_uri is None)
        self.assertTrue(partial.terms_of_service is None)
        self.assertTrue(partial.recovery_token is None)


    def test_partial_account_default(self):
        partial = account.Account(self.config, self.key)
        partial.save()

        acc = account.Account.from_existing_account(self.config)

        self.assertEqual(partial.key, acc.key)
        self.assertEqual(partial.email, acc.email)
        self.assertEqual(partial.phone, acc.phone)
        self.assertEqual(partial.regr, acc.regr)

    @mock.patch("letsencrypt.client.account.display_ops.choose_account")
    def test_choose_account(self, mock_op):
        mock_op.return_value = self.test_account

        # Test 0
        self.assertTrue(account.Account.choose_account(self.config) is None)

        # Test 1
        self.test_account.save()
        acc = account.Account.choose_account(self.config)
        self.assertEqual(acc.email, self.test_account.email)

        # Test multiple
        self.assertFalse(mock_op.called)
        acc2 = account.Account(self.config, self.key)
        acc2.save()
        test_acc = account.Account.choose_account(self.config)
        self.assertTrue(mock_op.called)
        self.assertTrue(test_acc.email, self.test_account.email)

    def _read_out_config(self, filep):
        print open(os.path.join(self.accounts_dir, filep)).read()


class SafeEmailTest(unittest.TestCase):
    """Test safe_email."""

    @classmethod
    def _call(cls, addr):
        from letsencrypt.client.account import Account
        return Account.safe_email(addr)

    def test_valid_emails(self):
        addrs = [
            "letsencrypt@letsencrypt.org",
            "tbd.ade@gmail.com",
            "abc_def.jdk@hotmail.museum"
        ]
        for addr in addrs:
            self.assertTrue(addr, "%s failed." % addr)

    def test_invalid_emails(self):
        addrs = [
            "letsencrypt@letsencrypt..org",
            ".tbd.ade@gmail.com",
            "~/abc_def.jdk@hotmail.museum"
        ]
        for addr in addrs:
            self.assertTrue(addr, "%s failed." % addr)


if __name__ == "__main__":
    unittest.main()
