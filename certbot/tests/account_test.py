"""Tests for certbot.account."""
import datetime
import json
import os
import shutil
import stat
import unittest

import mock
import pytz

from acme import jose
from acme import messages

from certbot import errors

import certbot.tests.util as test_util


KEY = jose.JWKRSA.load(test_util.load_vector("rsa512_key.pem"))


class AccountTest(unittest.TestCase):
    """Tests for certbot.account.Account."""

    def setUp(self):
        from certbot.account import Account
        self.regr = mock.MagicMock()
        self.meta = Account.Meta(
            creation_host="test.certbot.org",
            creation_dt=datetime.datetime(
                2015, 7, 4, 14, 4, 10, tzinfo=pytz.UTC))
        self.acc = Account(self.regr, KEY, self.meta)
        self.regr.__repr__ = mock.MagicMock(return_value="i_am_a_regr")

        with mock.patch("certbot.account.socket") as mock_socket:
            mock_socket.getfqdn.return_value = "test.certbot.org"
            with mock.patch("certbot.account.datetime") as mock_dt:
                mock_dt.datetime.now.return_value = self.meta.creation_dt
                self.acc_no_meta = Account(self.regr, KEY)

    def test_init(self):
        self.assertEqual(self.regr, self.acc.regr)
        self.assertEqual(KEY, self.acc.key)
        self.assertEqual(self.meta, self.acc_no_meta.meta)

    def test_id(self):
        self.assertEqual(
            self.acc.id, "7adac10320f585ddf118429c0c4af2cd")

    def test_slug(self):
        self.assertEqual(
            self.acc.slug, "test.certbot.org@2015-07-04T14:04:10Z (7ada)")

    def test_repr(self):
        self.assertTrue(repr(self.acc).startswith(
          "<Account(i_am_a_regr, 7adac10320f585ddf118429c0c4af2cd, Meta("))

class ReportNewAccountTest(test_util.ConfigTestCase):
    """Tests for certbot.account.report_new_account."""

    def _call(self):
        from certbot.account import report_new_account
        report_new_account(self.config)

    @mock.patch("certbot.account.zope.component.queryUtility")
    def test_no_reporter(self, mock_zope):
        mock_zope.return_value = None
        self._call()

    @mock.patch("certbot.account.zope.component.queryUtility")
    def test_it(self, mock_zope):
        self._call()
        call_list = mock_zope().add_message.call_args_list
        self.assertTrue(self.config.config_dir in call_list[0][0][0])


class AccountMemoryStorageTest(unittest.TestCase):
    """Tests for certbot.account.AccountMemoryStorage."""

    def setUp(self):
        from certbot.account import AccountMemoryStorage
        self.storage = AccountMemoryStorage()

    def test_it(self):
        account = mock.Mock(id="x")
        self.assertEqual([], self.storage.find_all())
        self.assertRaises(errors.AccountNotFound, self.storage.load, "x")
        self.storage.save(account, None)
        self.assertEqual([account], self.storage.find_all())
        self.assertEqual(account, self.storage.load("x"))
        self.storage.save(account, None)
        self.assertEqual([account], self.storage.find_all())


class AccountFileStorageTest(test_util.ConfigTestCase):
    """Tests for certbot.account.AccountFileStorage."""

    def setUp(self):
        super(AccountFileStorageTest, self).setUp()

        from certbot.account import AccountFileStorage
        self.storage = AccountFileStorage(self.config)

        from certbot.account import Account
        new_authzr_uri = "hi"
        self.acc = Account(
            regr=messages.RegistrationResource(
                uri=None, body=messages.Registration(),
                new_authzr_uri=new_authzr_uri),
            key=KEY)
        self.mock_client = mock.MagicMock()
        self.mock_client.directory.new_authz = new_authzr_uri

    def test_init_creates_dir(self):
        self.assertTrue(os.path.isdir(self.config.accounts_dir))

    def test_save_and_restore(self):
        self.storage.save(self.acc, self.mock_client)
        account_path = os.path.join(self.config.accounts_dir, self.acc.id)
        self.assertTrue(os.path.exists(account_path))
        for file_name in "regr.json", "meta.json", "private_key.json":
            self.assertTrue(os.path.exists(
                os.path.join(account_path, file_name)))
        self.assertTrue(oct(os.stat(os.path.join(
            account_path, "private_key.json"))[stat.ST_MODE] & 0o777) in ("0400", "0o400"))

        # restore
        loaded = self.storage.load(self.acc.id)
        self.assertEqual(self.acc, loaded)

    def test_save_and_restore_old_version(self):
        """Saved regr should include a new_authzr_uri for older Certbots"""
        self.storage.save(self.acc, self.mock_client)
        path = os.path.join(self.config.accounts_dir, self.acc.id, "regr.json")
        with open(path, "r") as f:
            regr = json.load(f)
        self.assertTrue("new_authzr_uri" in regr)

    def test_save_regr(self):
        self.storage.save_regr(self.acc, self.mock_client)
        account_path = os.path.join(self.config.accounts_dir, self.acc.id)
        self.assertTrue(os.path.exists(account_path))
        self.assertTrue(os.path.exists(os.path.join(
            account_path, "regr.json")))
        for file_name in "meta.json", "private_key.json":
            self.assertFalse(os.path.exists(
                os.path.join(account_path, file_name)))

    def test_find_all(self):
        self.storage.save(self.acc, self.mock_client)
        self.assertEqual([self.acc], self.storage.find_all())

    def test_find_all_none_empty_list(self):
        self.assertEqual([], self.storage.find_all())

    def test_find_all_accounts_dir_absent(self):
        os.rmdir(self.config.accounts_dir)
        self.assertEqual([], self.storage.find_all())

    def test_find_all_load_skips(self):
        self.storage.load = mock.MagicMock(
            side_effect=["x", errors.AccountStorageError, "z"])
        with mock.patch("certbot.account.os.listdir") as mock_listdir:
            mock_listdir.return_value = ["x", "y", "z"]
            self.assertEqual(["x", "z"], self.storage.find_all())

    def test_load_non_existent_raises_error(self):
        self.assertRaises(errors.AccountNotFound, self.storage.load, "missing")

    def test_load_id_mismatch_raises_error(self):
        self.storage.save(self.acc, self.mock_client)
        shutil.move(os.path.join(self.config.accounts_dir, self.acc.id),
                    os.path.join(self.config.accounts_dir, "x" + self.acc.id))
        self.assertRaises(errors.AccountStorageError, self.storage.load,
                          "x" + self.acc.id)

    def test_load_ioerror(self):
        self.storage.save(self.acc, self.mock_client)
        mock_open = mock.mock_open()
        mock_open.side_effect = IOError
        with mock.patch("six.moves.builtins.open", mock_open):
            self.assertRaises(
                errors.AccountStorageError, self.storage.load, self.acc.id)

    def test_save_ioerrors(self):
        mock_open = mock.mock_open()
        mock_open.side_effect = IOError  # TODO: [None, None, IOError]
        with mock.patch("six.moves.builtins.open", mock_open):
            self.assertRaises(
                errors.AccountStorageError, self.storage.save,
                    self.acc, self.mock_client)

    def test_delete(self):
        self.storage.save(self.acc, self.mock_client)
        self.storage.delete(self.acc.id)
        self.assertRaises(errors.AccountNotFound, self.storage.load, self.acc.id)

    def test_delete_no_account(self):
        self.assertRaises(errors.AccountNotFound, self.storage.delete, self.acc.id)


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
