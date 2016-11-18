"""Tests for certbot.main."""
import os
import shutil
import tempfile
import unittest
import datetime
import pytz

import mock

from certbot import cli
from certbot import account
from certbot import colored_logging
from certbot import constants
from certbot import configuration
from certbot import errors
from certbot.plugins import disco as plugins_disco

from certbot.tests import test_util
from acme import jose

CERT_PATH = test_util.vector_path('cert.pem')
KEY = jose.JWKRSA.load(test_util.load_vector("rsa512_key_2.pem"))

class MainTest(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_handle_identical_cert_request_pending(self):
        from certbot import main
        mock_lineage = mock.Mock()
        mock_lineage.ensure_deployed.return_value = False
        # pylint: disable=protected-access
        ret = main._handle_identical_cert_request(mock.Mock(), mock_lineage)
        self.assertEqual(ret, ("reinstall", mock_lineage))


class RunTest(unittest.TestCase):
    """Tests for certbot.main.run."""

    def setUp(self):
        self.domain = 'example.org'
        self.patches = [
            mock.patch('certbot.main._auth_from_domains'),
            mock.patch('certbot.main.display_ops.success_installation'),
            mock.patch('certbot.main.display_ops.success_renewal'),
            mock.patch('certbot.main._init_le_client'),
            mock.patch('certbot.main._suggest_donation_if_appropriate')]

        self.mock_auth = self.patches[0].start()
        self.mock_success_installation = self.patches[1].start()
        self.mock_success_renewal = self.patches[2].start()
        self.mock_init = self.patches[3].start()
        self.mock_suggest_donation = self.patches[4].start()

    def tearDown(self):
        for patch in self.patches:
            patch.stop()

    def _call(self):
        args = '-a webroot -i null -d {0}'.format(self.domain).split()
        plugins = plugins_disco.PluginsRegistry.find_all()
        config = configuration.NamespaceConfig(
            cli.prepare_and_parse_args(plugins, args))

        from certbot.main import run
        run(config, plugins)

    def test_newcert_success(self):
        self.mock_auth.return_value = ('newcert', mock.Mock())
        self._call()
        self.mock_success_installation.assert_called_once_with([self.domain])

    def test_reinstall_success(self):
        self.mock_auth.return_value = ('reinstall', mock.Mock())
        self._call()
        self.mock_success_installation.assert_called_once_with([self.domain])

    def test_renewal_success(self):
        self.mock_auth.return_value = ('renewal', mock.Mock())
        self._call()
        self.mock_success_renewal.assert_called_once_with([self.domain])


class ObtainCertTest(unittest.TestCase):
    """Tests for certbot.main.obtain_cert."""

    def setUp(self):
        self.get_utility_patch = mock.patch(
            'certbot.main.zope.component.getUtility')
        self.mock_get_utility = self.get_utility_patch.start()

    def tearDown(self):
        self.get_utility_patch.stop()

    def _call(self, args):
        plugins = plugins_disco.PluginsRegistry.find_all()
        config = configuration.NamespaceConfig(
            cli.prepare_and_parse_args(plugins, args))

        from certbot import main
        with mock.patch('certbot.main._init_le_client') as mock_init:
            main.obtain_cert(config, plugins)

        return mock_init()  # returns the client

    @mock.patch('certbot.main._auth_from_domains')
    def test_no_reinstall_text_pause(self, mock_auth):
        mock_notification = self.mock_get_utility().notification
        mock_notification.side_effect = self._assert_no_pause
        mock_auth.return_value = ('reinstall', mock.ANY)
        self._call('certonly --webroot -d example.com'.split())

    def _assert_no_pause(self, message, pause=True):
        # pylint: disable=unused-argument
        self.assertFalse(pause)

class RevokeTest(unittest.TestCase):
    """Tests for certbot.main.revoke."""

    def setUp(self):
        self.tempdir_path = tempfile.mkdtemp()
        shutil.copy(CERT_PATH, self.tempdir_path)
        self.tmp_cert_path = os.path.abspath(os.path.join(self.tempdir_path,
            'cert.pem'))

        self.patches = [
            mock.patch('acme.client.Client'),
            mock.patch('certbot.client.Client'),
            mock.patch('certbot.main._determine_account'),
            mock.patch('certbot.main.display_ops.success_revocation')
        ]
        self.mock_acme_client = self.patches[0].start()
        self.patches[1].start()
        self.mock_determine_account = self.patches[2].start()
        self.mock_success_revoke = self.patches[3].start()

        from certbot.account import Account

        self.regr = mock.MagicMock()
        self.meta = Account.Meta(
            creation_host="test.certbot.org",
            creation_dt=datetime.datetime(
                2015, 7, 4, 14, 4, 10, tzinfo=pytz.UTC))
        self.acc = Account(self.regr, KEY, self.meta)

        self.mock_determine_account.return_value = (self.acc, None)


    def tearDown(self):
        shutil.rmtree(self.tempdir_path)
        for patch in self.patches:
            patch.stop()

    def _call(self):
        args = 'revoke --cert-path={0}'.format(self.tmp_cert_path).split()
        plugins = plugins_disco.PluginsRegistry.find_all()
        config = configuration.NamespaceConfig(
            cli.prepare_and_parse_args(plugins, args))

        from certbot.main import revoke
        revoke(config, plugins)

    def test_revocation_success(self):
        self._call()
        self.mock_success_revoke.assert_called_once_with(self.tmp_cert_path)

    def test_revocation_error(self):
        from acme import errors as acme_errors
        self.mock_acme_client.side_effect = acme_errors.ClientError()
        self.assertRaises(acme_errors.ClientError, self._call)
        self.mock_success_revoke.assert_not_called()

class SetupLogFileHandlerTest(unittest.TestCase):
    """Tests for certbot.main.setup_log_file_handler."""

    def setUp(self):
        self.config = mock.Mock(spec_set=['logs_dir'],
                                logs_dir=tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.config.logs_dir)

    def _call(self, *args, **kwargs):
        from certbot.main import setup_log_file_handler
        return setup_log_file_handler(*args, **kwargs)

    @mock.patch('certbot.main.logging.handlers.RotatingFileHandler')
    def test_ioerror(self, mock_handler):
        mock_handler.side_effect = IOError
        self.assertRaises(errors.Error, self._call,
                          self.config, "test.log", "%s")


class SetupLoggingTest(unittest.TestCase):
    """Tests for certbot.main.setup_logging."""

    def setUp(self):
        self.config = mock.Mock(
            logs_dir=tempfile.mkdtemp(),
            noninteractive_mode=False, quiet=False,
            verbose_count=constants.CLI_DEFAULTS['verbose_count'])

    def tearDown(self):
        shutil.rmtree(self.config.logs_dir)

    @classmethod
    def _call(cls, *args, **kwargs):
        from certbot.main import setup_logging
        return setup_logging(*args, **kwargs)

    @mock.patch('certbot.main.logging.getLogger')
    def test_defaults(self, mock_get_logger):
        self._call(self.config)

        cli_handler = mock_get_logger().addHandler.call_args_list[0][0][0]
        self.assertEqual(cli_handler.level, -self.config.verbose_count * 10)
        self.assertTrue(
            isinstance(cli_handler, colored_logging.StreamHandler))

    @mock.patch('certbot.main.logging.getLogger')
    def test_quiet_mode(self, mock_get_logger):
        self.config.quiet = self.config.noninteractive_mode = True
        self._call(self.config)

        cli_handler = mock_get_logger().addHandler.call_args_list[0][0][0]
        self.assertEqual(cli_handler.level, constants.QUIET_LOGGING_LEVEL)
        self.assertTrue(
            isinstance(cli_handler, colored_logging.StreamHandler))


class MakeOrVerifyCoreDirTest(unittest.TestCase):
    """Tests for certbot.main.make_or_verify_core_dir."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.dir)

    def _call(self, *args, **kwargs):
        from certbot.main import make_or_verify_core_dir
        return make_or_verify_core_dir(*args, **kwargs)

    def test_success(self):
        new_dir = os.path.join(self.dir, 'new')
        self._call(new_dir, 0o700, os.geteuid(), False)
        self.assertTrue(os.path.exists(new_dir))

    @mock.patch('certbot.main.util.make_or_verify_dir')
    def test_failure(self, mock_make_or_verify):
        mock_make_or_verify.side_effect = OSError
        self.assertRaises(errors.Error, self._call,
                          self.dir, 0o700, os.geteuid(), False)


class DetermineAccountTest(unittest.TestCase):
    """Tests for certbot.main._determine_account."""

    def setUp(self):
        self.args = mock.MagicMock(account=None, email=None,
            register_unsafely_without_email=False)
        self.config = configuration.NamespaceConfig(self.args)
        self.accs = [mock.MagicMock(id='x'), mock.MagicMock(id='y')]
        self.account_storage = account.AccountMemoryStorage()

    def _call(self):
        # pylint: disable=protected-access
        from certbot.main import _determine_account
        with mock.patch('certbot.main.account.AccountFileStorage') as mock_storage:
            mock_storage.return_value = self.account_storage
            return _determine_account(self.config)

    def test_args_account_set(self):
        self.account_storage.save(self.accs[1])
        self.config.account = self.accs[1].id
        self.assertEqual((self.accs[1], None), self._call())
        self.assertEqual(self.accs[1].id, self.config.account)
        self.assertTrue(self.config.email is None)

    def test_single_account(self):
        self.account_storage.save(self.accs[0])
        self.assertEqual((self.accs[0], None), self._call())
        self.assertEqual(self.accs[0].id, self.config.account)
        self.assertTrue(self.config.email is None)

    @mock.patch('certbot.client.display_ops.choose_account')
    def test_multiple_accounts(self, mock_choose_accounts):
        for acc in self.accs:
            self.account_storage.save(acc)
        mock_choose_accounts.return_value = self.accs[1]
        self.assertEqual((self.accs[1], None), self._call())
        self.assertEqual(
            set(mock_choose_accounts.call_args[0][0]), set(self.accs))
        self.assertEqual(self.accs[1].id, self.config.account)
        self.assertTrue(self.config.email is None)

    @mock.patch('certbot.client.display_ops.get_email')
    def test_no_accounts_no_email(self, mock_get_email):
        mock_get_email.return_value = 'foo@bar.baz'

        with mock.patch('certbot.main.client') as client:
            client.register.return_value = (
                self.accs[0], mock.sentinel.acme)
            self.assertEqual((self.accs[0], mock.sentinel.acme), self._call())
        client.register.assert_called_once_with(
            self.config, self.account_storage, tos_cb=mock.ANY)

        self.assertEqual(self.accs[0].id, self.config.account)
        self.assertEqual('foo@bar.baz', self.config.email)

    def test_no_accounts_email(self):
        self.config.email = 'other email'
        with mock.patch('certbot.main.client') as client:
            client.register.return_value = (self.accs[1], mock.sentinel.acme)
            self._call()
        self.assertEqual(self.accs[1].id, self.config.account)
        self.assertEqual('other email', self.config.email)


class DuplicativeCertsTest(storage_test.BaseRenewableCertTest):
    """Test to avoid duplicate lineages."""

    def setUp(self):
        super(DuplicativeCertsTest, self).setUp()
        self.config.write()
        self._write_out_ex_kinds()

    def tearDown(self):
        shutil.rmtree(self.tempdir)

    @mock.patch('certbot.util.make_or_verify_dir')
    def test_find_duplicative_names(self, unused_makedir):
        from certbot.main import _find_duplicative_certs
        test_cert = test_util.load_vector('cert-san.pem')
        with open(self.test_rc.cert, 'wb') as f:
            f.write(test_cert)

        # No overlap at all
        result = _find_duplicative_certs(
            self.cli_config, ['wow.net', 'hooray.org'])
        self.assertEqual(result, (None, None))

        # Totally identical
        result = _find_duplicative_certs(
            self.cli_config, ['example.com', 'www.example.com'])
        self.assertTrue(result[0].configfile.filename.endswith('example.org.conf'))
        self.assertEqual(result[1], None)

        # Superset
        result = _find_duplicative_certs(
            self.cli_config, ['example.com', 'www.example.com', 'something.new'])
        self.assertEqual(result[0], None)
        self.assertTrue(result[1].configfile.filename.endswith('example.org.conf'))

        # Partial overlap doesn't count
        result = _find_duplicative_certs(
            self.cli_config, ['example.com', 'something.new'])
        self.assertEqual(result, (None, None))


if __name__ == '__main__':
    unittest.main()  # pragma: no cover
