"""Tests for letsencrypt.client.account."""
import logging
import mock
import os
import pkg_resources
import shutil
import tempfile
import unittest

from letsencrypt.acme import messages2

from letsencrypt.client import configuration
from letsencrypt.client import errors
from letsencrypt.client import le_util

from letsencrypt.client.display import util as display_util


class AccountTest(unittest.TestCase):
    """Tests letsencrypt.client.account.Account."""

    def setUp(self):
        from letsencrypt.client.account import Account

        logging.disable(logging.CRITICAL)

        self.accounts_dir = tempfile.mkdtemp("accounts")
        self.account_keys_dir = os.path.join(self.accounts_dir, "keys")
        os.makedirs(self.account_keys_dir, 0o700)

        self.config = mock.MagicMock(
            spec=configuration.NamespaceConfig, accounts_dir=self.accounts_dir,
            account_keys_dir=self.account_keys_dir, rsa_key_size=2048,
            server="letsencrypt-demo.org")

        key_file = pkg_resources.resource_filename(
            "letsencrypt.acme.jose", os.path.join("testdata", "rsa512_key.pem"))
        key_pem = pkg_resources.resource_string(
            "letsencrypt.acme.jose", os.path.join("testdata", "rsa512_key.pem"))

        self.key = le_util.Key(key_file, key_pem)
        self.email = "client@letsencrypt.org"
        self.regr = messages2.RegistrationResource(
            uri="uri",
            new_authzr_uri="new_authzr_uri",
            terms_of_service="terms_of_service",
            body=messages2.Registration(
                recovery_token="recovery_token", agreement="agreement")
        )

        self.test_account = Account(
            self.config, self.key, self.email, None, self.regr)

    def tearDown(self):
        shutil.rmtree(self.accounts_dir)
        logging.disable(logging.NOTSET)

    @mock.patch("letsencrypt.client.account.zope.component.getUtility")
    @mock.patch("letsencrypt.client.account.crypto_util.init_save_key")
    def test_prompts(self, mock_key, mock_util):
        from letsencrypt.client.account import Account

        mock_util().input.return_value = (display_util.OK, self.email)
        mock_key.return_value = self.key

        acc = Account.from_prompts(self.config)
        self.assertEqual(acc.email, self.email)
        self.assertEqual(acc.key, self.key)
        self.assertEqual(acc.config, self.config)

    @mock.patch("letsencrypt.client.account.zope.component.getUtility")
    @mock.patch("letsencrypt.client.account.Account.from_email")
    def test_prompts_bad_email(self, mock_from_email, mock_util):
        from letsencrypt.client.account import Account

        mock_from_email.side_effect = (errors.LetsEncryptClientError, "acc")
        mock_util().input.return_value = (display_util.OK, self.email)

        self.assertEqual(Account.from_prompts(self.config), "acc")


    @mock.patch("letsencrypt.client.account.zope.component.getUtility")
    @mock.patch("letsencrypt.client.account.crypto_util.init_save_key")
    def test_prompts_empty_email(self, mock_key, mock_util):
        from letsencrypt.client.account import Account

        mock_util().input.return_value = (display_util.OK, "")
        acc = Account.from_prompts(self.config)
        self.assertTrue(acc.email is None)
        # _get_config_filename | pylint: disable=protected-access
        mock_key.assert_called_once_with(
            mock.ANY, mock.ANY, acc._get_config_filename(None))

    @mock.patch("letsencrypt.client.account.zope.component.getUtility")
    def test_prompts_cancel(self, mock_util):
        from letsencrypt.client.account import Account

        mock_util().input.return_value = (display_util.CANCEL, "")

        self.assertTrue(Account.from_prompts(self.config) is None)

    def test_from_email(self):
        from letsencrypt.client.account import Account

        self.assertRaises(errors.LetsEncryptClientError,
                          Account.from_email, self.config, "not_valid...email")

    def test_save_from_existing_account(self):
        from letsencrypt.client.account import Account

        self.test_account.save()
        acc = Account.from_existing_account(self.config, self.email)

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
        from letsencrypt.client.account import Account

        partial = Account(self.config, self.key)

        self.assertTrue(partial.uri is None)
        self.assertTrue(partial.new_authzr_uri is None)
        self.assertTrue(partial.terms_of_service is None)
        self.assertTrue(partial.recovery_token is None)

    def test_partial_account_default(self):
        from letsencrypt.client.account import Account

        partial = Account(self.config, self.key)
        partial.save()

        acc = Account.from_existing_account(self.config)

        self.assertEqual(partial.key, acc.key)
        self.assertEqual(partial.email, acc.email)
        self.assertEqual(partial.phone, acc.phone)
        self.assertEqual(partial.regr, acc.regr)

    def test_get_accounts(self):
        from letsencrypt.client.account import Account

        accs = Account.get_accounts(self.config)
        self.assertFalse(accs)

        self.test_account.save()
        accs = Account.get_accounts(self.config)
        self.assertEqual(len(accs), 1)
        self.assertEqual(accs[0].email, self.test_account.email)

        acc2 = Account(self.config, self.key, "testing_email@gmail.com")
        acc2.save()
        accs = Account.get_accounts(self.config)
        self.assertEqual(len(accs), 2)

    def test_get_accounts_no_accounts(self):
        from letsencrypt.client.account import Account

        self.assertEqual(Account.get_accounts(
            mock.Mock(accounts_dir="non-existant")), [])

    def test_failed_existing_account(self):
        from letsencrypt.client.account import Account

        self.assertRaises(
            errors.LetsEncryptClientError,
            Account.from_existing_account,
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
            "abc_def.jdk@hotmail.museum",
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
    unittest.main()  # pragma: no cover
