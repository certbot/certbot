"""Tests for letsencrypt.account."""
import datetime
import os
import shutil
import stat
import tempfile
import unittest

import mock
import pytz

from acme import jose
from acme import messages

from letsencrypt import errors

from letsencrypt.tests import test_util


KEY = jose.JWKRSA.load(test_util.load_vector("rsa512_key_2.pem"))


class AccountTest(unittest.TestCase):
    """Tests for letsencrypt.account.Account."""

    def setUp(self):
        from letsencrypt.account import Account
        self.regr = mock.MagicMock()
        self.meta = Account.Meta(
            creation_host="test.letsencrypt.org",
            creation_dt=datetime.datetime(
                2015, 7, 4, 14, 4, 10, tzinfo=pytz.UTC))
        self.acc = Account(self.regr, KEY, self.meta)

        with mock.patch("letsencrypt.account.socket") as mock_socket:
            mock_socket.getfqdn.return_value = "test.letsencrypt.org"
            with mock.patch("letsencrypt.account.datetime") as mock_dt:
                mock_dt.datetime.now.return_value = self.meta.creation_dt
                self.acc_no_meta = Account(self.regr, KEY)

    def test_init(self):
        self.assertEqual(self.regr, self.acc.regr)
        self.assertEqual(KEY, self.acc.key)
        self.assertEqual(self.meta, self.acc_no_meta.meta)

    def test_id(self):
        self.assertEqual(
            self.acc.id, "bca5889f66457d5b62fbba7b25f9ab6f")

    def test_slug(self):
        self.assertEqual(
            self.acc.slug, "test.letsencrypt.org@2015-07-04T14:04:10Z (bca5)")

    def test_repr(self):
        self.assertEqual(
            repr(self.acc),
            "<Account(bca5889f66457d5b62fbba7b25f9ab6f)>")


class ReportNewAccountTest(unittest.TestCase):
    """Tests for letsencrypt.account.report_new_account."""

    def setUp(self):
        self.config = mock.MagicMock(config_dir="/etc/letsencrypt")
        reg = messages.Registration.from_data(email="rhino@jungle.io")
        self.acc = mock.MagicMock(regr=messages.RegistrationResource(
            uri=None, new_authzr_uri=None, body=reg))

    def _call(self):
        from letsencrypt.account import report_new_account
        report_new_account(self.acc, self.config)

    @mock.patch("letsencrypt.account.zope.component.queryUtility")
    def test_no_reporter(self, mock_zope):
        mock_zope.return_value = None
        self._call()

    @mock.patch("letsencrypt.account.zope.component.queryUtility")
    def test_it(self, mock_zope):
        self._call()
        call_list = mock_zope().add_message.call_args_list
        self.assertTrue(self.config.config_dir in call_list[0][0][0])
        self.assertTrue(
            ", ".join(self.acc.regr.body.emails) in call_list[1][0][0])


class AccountMemoryStorageTest(unittest.TestCase):
    """Tests for letsencrypt.account.AccountMemoryStorage."""

    def setUp(self):
        from letsencrypt.account import AccountMemoryStorage
        self.storage = AccountMemoryStorage()

    def test_it(self):
        account = mock.Mock(id="x")
        self.assertEqual([], self.storage.find_all())
        self.assertRaises(errors.AccountNotFound, self.storage.load, "x")
        self.storage.save(account)
        self.assertEqual([account], self.storage.find_all())
        self.assertEqual(account, self.storage.load("x"))
        self.storage.save(account)
        self.assertEqual([account], self.storage.find_all())


class AccountFileStorageTest(unittest.TestCase):
    """Tests for letsencrypt.account.AccountFileStorage."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.config = mock.MagicMock(
            accounts_dir=os.path.join(self.tmp, "accounts"))
        from letsencrypt.account import AccountFileStorage
        self.storage = AccountFileStorage(self.config)

        from letsencrypt.account import Account
        self.acc = Account(
            regr=messages.RegistrationResource(
                uri=None, new_authzr_uri=None, body=messages.Registration()),
            key=KEY)

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_init_creates_dir(self):
        self.assertTrue(os.path.isdir(self.config.accounts_dir))

    def test_save_and_restore(self):
        self.storage.save(self.acc)
        account_path = os.path.join(self.config.accounts_dir, self.acc.id)
        self.assertTrue(os.path.exists(account_path))
        for file_name in "regr.json", "meta.json", "private_key.json":
            self.assertTrue(os.path.exists(
                os.path.join(account_path, file_name)))
        self.assertEqual("0400", oct(os.stat(os.path.join(
            account_path, "private_key.json"))[stat.ST_MODE] & 0o777))

        # restore
        self.assertEqual(self.acc, self.storage.load(self.acc.id))

    def test_find_all(self):
        self.storage.save(self.acc)
        self.assertEqual([self.acc], self.storage.find_all())

    def test_find_all_none_empty_list(self):
        self.assertEqual([], self.storage.find_all())

    def test_find_all_accounts_dir_absent(self):
        os.rmdir(self.config.accounts_dir)
        self.assertEqual([], self.storage.find_all())

    def test_find_all_load_skips(self):
        self.storage.load = mock.MagicMock(
            side_effect=["x", errors.AccountStorageError, "z"])
        with mock.patch("letsencrypt.account.os.listdir") as mock_listdir:
            mock_listdir.return_value = ["x", "y", "z"]
            self.assertEqual(["x", "z"], self.storage.find_all())

    def test_load_non_existent_raises_error(self):
        self.assertRaises(errors.AccountNotFound, self.storage.load, "missing")

    def test_load_id_mismatch_raises_error(self):
        self.storage.save(self.acc)
        shutil.move(os.path.join(self.config.accounts_dir, self.acc.id),
                    os.path.join(self.config.accounts_dir, "x" + self.acc.id))
        self.assertRaises(errors.AccountStorageError, self.storage.load,
                          "x" + self.acc.id)

    def test_load_ioerror(self):
        self.storage.save(self.acc)
        mock_open = mock.mock_open()
        mock_open.side_effect = IOError
        with mock.patch("__builtin__.open", mock_open):
            self.assertRaises(
                errors.AccountStorageError, self.storage.load, self.acc.id)

    def test_save_ioerrors(self):
        mock_open = mock.mock_open()
        mock_open.side_effect = IOError  # TODO: [None, None, IOError]
        with mock.patch("__builtin__.open", mock_open):
            self.assertRaises(
                errors.AccountStorageError, self.storage.save, self.acc)


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
