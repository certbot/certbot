"""Tests for letsencrypt.cli."""
import itertools
import os
import shutil
import traceback
import tempfile
import unittest

import mock

from letsencrypt import account
from letsencrypt import configuration
from letsencrypt import errors

from letsencrypt.tests import renewer_test
from letsencrypt.tests import test_util


class CLITest(unittest.TestCase):
    """Tests for different commands."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.config_dir = os.path.join(self.tmp_dir, 'config')
        self.work_dir = os.path.join(self.tmp_dir, 'work')
        self.logs_dir = os.path.join(self.tmp_dir, 'logs')

    def tearDown(self):
        shutil.rmtree(self.tmp_dir)

    def _call(self, args):
        from letsencrypt import cli
        args = ['--text', '--config-dir', self.config_dir,
                '--work-dir', self.work_dir, '--logs-dir', self.logs_dir,
                '--agree-eula'] + args
        with mock.patch('letsencrypt.cli.sys.stdout') as stdout:
            with mock.patch('letsencrypt.cli.sys.stderr') as stderr:
                with mock.patch('letsencrypt.cli.client') as client:
                    ret = cli.main(args)
        return ret, stdout, stderr, client

    def test_no_flags(self):
        self.assertRaises(SystemExit, self._call, [])

    def test_help(self):
        self.assertRaises(SystemExit, self._call, ['--help'])
        self.assertRaises(SystemExit, self._call, ['--help all'])

    def test_rollback(self):
        _, _, _, client = self._call(['rollback'])
        self.assertEqual(1, client.rollback.call_count)

        _, _, _, client = self._call(['rollback', '--checkpoints', '123'])
        client.rollback.assert_called_once_with(
            mock.ANY, 123, mock.ANY, mock.ANY)

    def test_config_changes(self):
        _, _, _, client = self._call(['config_changes'])
        self.assertEqual(1, client.view_config_changes.call_count)

    def test_plugins(self):
        flags = ['--init', '--prepare', '--authenticators', '--installers']
        for args in itertools.chain(
                *(itertools.combinations(flags, r)
                  for r in xrange(len(flags)))):
            self._call(['plugins'] + list(args))

    @mock.patch("letsencrypt.cli.sys")
    def test_handle_exception(self, mock_sys):
        # pylint: disable=protected-access
        from letsencrypt import cli

        mock_open = mock.mock_open()
        with mock.patch("letsencrypt.cli.open", mock_open, create=True):
            exception = Exception("detail")
            cli._handle_exception(
                Exception, exc_value=exception, trace=None, args=None)
            mock_open().write.assert_called_once_with("".join(
                traceback.format_exception_only(Exception, exception)))
            error_msg = mock_sys.exit.call_args_list[0][0][0]
            self.assertTrue("unexpected error" in error_msg)

        with mock.patch("letsencrypt.cli.open", mock_open, create=True):
            mock_open.side_effect = [KeyboardInterrupt]
            error = errors.Error("detail")
            cli._handle_exception(
                errors.Error, exc_value=error, trace=None, args=None)
            # assert_any_call used because sys.exit doesn't exit in cli.py
            mock_sys.exit.assert_any_call("".join(
                traceback.format_exception_only(errors.Error, error)))

        args = mock.MagicMock(debug=False)
        cli._handle_exception(
            Exception, exc_value=Exception("detail"), trace=None, args=args)
        error_msg = mock_sys.exit.call_args_list[-1][0][0]
        self.assertTrue("unexpected error" in error_msg)

        interrupt = KeyboardInterrupt("detail")
        cli._handle_exception(
            KeyboardInterrupt, exc_value=interrupt, trace=None, args=None)
        mock_sys.exit.assert_called_with("".join(
            traceback.format_exception_only(KeyboardInterrupt, interrupt)))


class DetermineAccountTest(unittest.TestCase):
    """Tests for letsencrypt.cli._determine_account."""

    def setUp(self):
        self.args = mock.MagicMock(account=None, email=None)
        self.config = configuration.NamespaceConfig(self.args)
        self.accs = [mock.MagicMock(id="x"), mock.MagicMock(id="y")]
        self.account_storage = account.AccountMemoryStorage()

    def _call(self):
        # pylint: disable=protected-access
        from letsencrypt.cli import _determine_account
        with mock.patch("letsencrypt.cli.account.AccountFileStorage") as mock_storage:
            mock_storage.return_value = self.account_storage
            return _determine_account(self.args, self.config)

    def test_args_account_set(self):
        self.account_storage.save(self.accs[1])
        self.args.account = self.accs[1].id
        self.assertEqual((self.accs[1], None), self._call())
        self.assertEqual(self.accs[1].id, self.args.account)
        self.assertTrue(self.args.email is None)

    def test_single_account(self):
        self.account_storage.save(self.accs[0])
        self.assertEqual((self.accs[0], None), self._call())
        self.assertEqual(self.accs[0].id, self.args.account)
        self.assertTrue(self.args.email is None)

    @mock.patch("letsencrypt.client.display_ops.choose_account")
    def test_multiple_accounts(self, mock_choose_accounts):
        for acc in self.accs:
            self.account_storage.save(acc)
        mock_choose_accounts.return_value = self.accs[1]
        self.assertEqual((self.accs[1], None), self._call())
        self.assertEqual(
            set(mock_choose_accounts.call_args[0][0]), set(self.accs))
        self.assertEqual(self.accs[1].id, self.args.account)
        self.assertTrue(self.args.email is None)

    @mock.patch("letsencrypt.client.display_ops.get_email")
    def test_no_accounts_no_email(self, mock_get_email):
        mock_get_email.return_value = "foo@bar.baz"

        with mock.patch("letsencrypt.cli.client") as client:
            client.register.return_value = (
                self.accs[0], mock.sentinel.acme)
            self.assertEqual((self.accs[0], mock.sentinel.acme), self._call())
        client.register.assert_called_once_with(
            self.config, self.account_storage, tos_cb=mock.ANY)

        self.assertEqual(self.accs[0].id, self.args.account)
        self.assertEqual("foo@bar.baz", self.args.email)

    def test_no_accounts_email(self):
        self.args.email = "other email"
        with mock.patch("letsencrypt.cli.client") as client:
            client.register.return_value = (self.accs[1], mock.sentinel.acme)
            self._call()
        self.assertEqual(self.accs[1].id, self.args.account)
        self.assertEqual("other email", self.args.email)


class DuplicativeCertsTest(renewer_test.BaseRenewableCertTest):
    """Test to avoid duplicate lineages."""

    def setUp(self):
        super(DuplicativeCertsTest, self).setUp()
        self.config.write()
        self._write_out_ex_kinds()

    def tearDown(self):
        shutil.rmtree(self.tempdir)

    def test_find_duplicative_names(self):
        from letsencrypt.cli import _find_duplicative_certs
        test_cert = test_util.load_vector("cert-san.pem")
        with open(self.test_rc.cert, "w") as f:
            f.write(test_cert)

        # No overlap at all
        result = _find_duplicative_certs(["wow.net", "hooray.org"],
                                         self.config, self.cli_config)
        self.assertEqual(result, (None, None))

        # Totally identical
        result = _find_duplicative_certs(["example.com", "www.example.com"],
                                         self.config, self.cli_config)
        self.assertTrue(result[0].configfile.filename.endswith("example.org.conf"))
        self.assertEqual(result[1], None)

        # Superset
        result = _find_duplicative_certs(["example.com", "www.example.com",
                                          "something.new"], self.config,
                                         self.cli_config)
        self.assertEqual(result[0], None)
        self.assertTrue(result[1].configfile.filename.endswith("example.org.conf"))

        # Partial overlap doesn't count
        result = _find_duplicative_certs(["example.com", "something.new"],
                                         self.config, self.cli_config)
        self.assertEqual(result, (None, None))


if __name__ == '__main__':
    unittest.main()  # pragma: no cover
