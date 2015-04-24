"""Tests for letsencrypt.client.account."""
import logging
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
from letsencrypt.client import errors
from letsencrypt.client import le_util

from letsencrypt.client.display import util as display_util


class AccountTest(unittest.TestCase):
    """Tests letsencrypt.client.account.Account."""

    def setUp(self):
        logging.disable(logging.CRITICAL)

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
        logging.disable(logging.NOTSET)

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

    @mock.patch("letsencrypt.client.account.zope.component.getUtility")
    def test_prompts_cancel(self, mock_util):
        # displayer = display_util.FileDisplay(sys.stdout)
        # zope.component.provideUtility(displayer)

        mock_util().input.return_value = (display_util.CANCEL, "")

        self.assertTrue(account.Account.from_prompts(self.config) is None)

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
        regr_no_authzr_uri = messages2.RegistrationResource(
            uri="uri",
            new_authzr_uri=None,
            terms_of_service="terms_of_service",
            body=messages2.Registration(
                recovery_token="recovery_token", agreement="agreement")
        )
        partial2 = account.Account(
            self.config, self.key, regr=regr_no_authzr_uri)

        self.assertTrue(partial.uri is None)
        self.assertTrue(partial.new_authzr_uri is None)
        self.assertTrue(partial.terms_of_service is None)
        self.assertTrue(partial.recovery_token is None)

        self.assertEqual(
            partial2.new_authzr_uri,
            "https://letsencrypt-demo.org/acme/new-authz")

    def test_partial_account_default(self):
        partial = account.Account(self.config, self.key)
        partial.save()

        acc = account.Account.from_existing_account(self.config)

        self.assertEqual(partial.key, acc.key)
        self.assertEqual(partial.email, acc.email)
        self.assertEqual(partial.phone, acc.phone)
        self.assertEqual(partial.regr, acc.regr)

    def test_get_accounts(self):
        accs = account.Account.get_accounts(self.config)
        self.assertFalse(accs)

        self.test_account.save()
        accs = account.Account.get_accounts(self.config)
        self.assertEqual(len(accs), 1)
        self.assertEqual(accs[0].email, self.test_account.email)

        acc2 = account.Account(self.config, self.key, "testing_email@gmail.com")
        acc2.save()
        accs = account.Account.get_accounts(self.config)
        self.assertEqual(len(accs), 2)

    def test_get_accounts_no_accounts(self):
        self.assertEqual(account.Account.get_accounts(
            mock.Mock(accounts_dir="non-existant")), [])

    def test_failed_existing_account(self):
        self.assertRaises(
            errors.LetsEncryptClientError,
            account.Account.from_existing_account,
            self.config, "non-existant@email.org")

class SafeEmailTest(unittest.TestCase):
    """Test safe_email."""
    def setUp(self):
        logging.disable(logging.CRITICAL)

    def tearDown(self):
        logging.disable(logging.NOTSET)

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
            self.assertTrue(self._call(addr), "%s failed." % addr)

    def test_invalid_emails(self):
        addrs = [
            "letsencrypt@letsencrypt..org",
            ".tbd.ade@gmail.com",
            "~/abc_def.jdk@hotmail.museum",
        ]
        for addr in addrs:
            self.assertFalse(self._call(addr), "%s failed." % addr)


if __name__ == "__main__":
    unittest.main()
