"""Tests for letsencrypt.cli."""
import itertools
import os
import shutil
import StringIO
import traceback
import tempfile
import unittest

import mock

from letsencrypt import account
from letsencrypt import configuration
from letsencrypt import errors

from letsencrypt.plugins import disco

from letsencrypt.tests import renewer_test
from letsencrypt.tests import test_util


CSR = test_util.vector_path('csr.der')


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
                '--agree-dev-preview'] + args
        with mock.patch('letsencrypt.cli.sys.stdout') as stdout:
            with mock.patch('letsencrypt.cli.sys.stderr') as stderr:
                with mock.patch('letsencrypt.cli.client') as client:
                    ret = cli.main(args)
        return ret, stdout, stderr, client

    def _call_stdout(self, args):
        """
        Variant of _call that preserves stdout so that it can be mocked by the
        caller.
        """
        from letsencrypt import cli
        args = ['--text', '--config-dir', self.config_dir,
                '--work-dir', self.work_dir, '--logs-dir', self.logs_dir,
                '--agree-dev-preview'] + args
        with mock.patch('letsencrypt.cli.sys.stderr') as stderr:
            with mock.patch('letsencrypt.cli.client') as client:
                ret = cli.main(args)
        return ret, None, stderr, client

    def test_no_flags(self):
        with MockedVerb("run") as mock_run:
            self._call([])
            self.assertEqual(1, mock_run.call_count)

    def _help_output(self, args):
        "Run a help command, and return the help string for scrutiny"
        output = StringIO.StringIO()
        with mock.patch('letsencrypt.cli.sys.stdout', new=output):
            self.assertRaises(SystemExit, self._call_stdout, args)
            out = output.getvalue()
            return out

    def test_help(self):
        self.assertRaises(SystemExit, self._call, ['--help'])
        self.assertRaises(SystemExit, self._call, ['--help', 'all'])
        plugins = disco.PluginsRegistry.find_all()
        out = self._help_output(['--help', 'all'])
        self.assertTrue("--configurator" in out)
        self.assertTrue("how a cert is deployed" in out)
        self.assertTrue("--manual-test-mode" in out)

        out = self._help_output(['-h', 'nginx'])
        if "nginx" in plugins:
            # may be false while building distributions without plugins
            self.assertTrue("--nginx-ctl" in out)
        self.assertTrue("--manual-test-mode" not in out)
        self.assertTrue("--checkpoints" not in out)

        out = self._help_output(['-h'])
        if "nginx" in plugins:
            self.assertTrue("Use the Nginx plugin" in out)
        else:
            self.assertTrue("(nginx support is experimental" in out)

        out = self._help_output(['--help', 'plugins'])
        self.assertTrue("--manual-test-mode" not in out)
        self.assertTrue("--prepare" in out)
        self.assertTrue("Plugin options" in out)

        out = self._help_output(['--help', 'install'])
        self.assertTrue("--cert-path" in out)
        self.assertTrue("--key-path" in out)

        out = self._help_output(['--help', 'revoke'])
        self.assertTrue("--cert-path" in out)
        self.assertTrue("--key-path" in out)

        out = self._help_output(['-h', 'config_changes'])
        self.assertTrue("--cert-path" not in out)
        self.assertTrue("--key-path" not in out)

        out = self._help_output(['-h'])
        from letsencrypt import cli
        self.assertTrue(cli.usage_strings(plugins)[0] in out)

    @mock.patch('letsencrypt.cli.display_ops')
    def test_installer_selection(self, mock_display_ops):
        self._call(['install', '--domain', 'foo.bar', '--cert-path', 'cert',
                    '--key-path', 'key', '--chain-path', 'chain'])
        self.assertEqual(mock_display_ops.pick_installer.call_count, 1)

    def test_configurator_selection(self):
        real_plugins = disco.PluginsRegistry.find_all()
        args = ['--agree-dev-preview', '--apache',
                '--authenticator', 'standalone']

        # This needed two calls to find_all(), which we're avoiding for now
        # because of possible side effects:
        # https://github.com/letsencrypt/letsencrypt/commit/51ed2b681f87b1eb29088dd48718a54f401e4855
        #with mock.patch('letsencrypt.cli.plugins_testable') as plugins:
        #    plugins.return_value = {"apache": True, "nginx": True}
        #    ret, _, _, _ = self._call(args)
        #    self.assertTrue("Too many flags setting" in ret)

        args = ["install", "--nginx", "--cert-path", "/tmp/blah", "--key-path", "/tmp/blah",
                "--nginx-server-root", "/nonexistent/thing", "-d",
                "example.com", "--debug"]
        if "nginx" in real_plugins:
            # Sending nginx a non-existent conf dir will simulate misconfiguration
            # (we can only do that if letsencrypt-nginx is actually present)
            ret, _, _, _ = self._call(args)
            self.assertTrue("The nginx plugin is not working" in ret)
            self.assertTrue("Could not find configuration root" in ret)
            self.assertTrue("NoInstallationError" in ret)

        with MockedVerb("certonly") as mock_certonly:
            self._call(["auth", "--standalone"])
            self.assertEqual(1, mock_certonly.call_count)

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

    def test_certonly_bad_args(self):
        ret, _, _, _ = self._call(['-d', 'foo.bar', 'certonly', '--csr', CSR])
        self.assertEqual(ret, '--domains and --csr are mutually exclusive')

        ret, _, _, _ = self._call(['-a', 'bad_auth', 'certonly'])
        self.assertEqual(ret, 'The requested bad_auth plugin does not appear to be installed')

    @mock.patch('letsencrypt.crypto_util.notAfter')
    @mock.patch('letsencrypt.cli.zope.component.getUtility')
    def test_certonly_new_request_success(self, mock_get_utility, mock_notAfter):
        cert_path = '/etc/letsencrypt/live/foo.bar'
        date = '1970-01-01'
        mock_notAfter().date.return_value = date

        mock_lineage = mock.MagicMock(cert=cert_path, fullchain=cert_path)
        mock_client = mock.MagicMock()
        mock_client.obtain_and_enroll_certificate.return_value = mock_lineage
        self._certonly_new_request_common(mock_client)
        self.assertEqual(
            mock_client.obtain_and_enroll_certificate.call_count, 1)
        self.assertTrue(
            cert_path in mock_get_utility().add_message.call_args[0][0])
        self.assertTrue(
            date in mock_get_utility().add_message.call_args[0][0])

    def test_certonly_new_request_failure(self):
        mock_client = mock.MagicMock()
        mock_client.obtain_and_enroll_certificate.return_value = False
        self.assertRaises(errors.Error,
                          self._certonly_new_request_common, mock_client)

    def _certonly_new_request_common(self, mock_client):
        with mock.patch('letsencrypt.cli._treat_as_renewal') as mock_renewal:
            mock_renewal.return_value = None
            with mock.patch('letsencrypt.cli._init_le_client') as mock_init:
                mock_init.return_value = mock_client
                self._call(['-d', 'foo.bar', '-a', 'standalone', 'certonly'])

    @mock.patch('letsencrypt.cli.zope.component.getUtility')
    @mock.patch('letsencrypt.cli._treat_as_renewal')
    @mock.patch('letsencrypt.cli._init_le_client')
    def test_certonly_renewal(self, mock_init, mock_renewal, mock_get_utility):
        cert_path = '/etc/letsencrypt/live/foo.bar/cert.pem'
        chain_path = '/etc/letsencrypt/live/foo.bar/fullchain.pem'

        mock_lineage = mock.MagicMock(cert=cert_path, fullchain=chain_path)
        mock_cert = mock.MagicMock(body='body')
        mock_key = mock.MagicMock(pem='pem_key')
        mock_renewal.return_value = mock_lineage
        mock_client = mock.MagicMock()
        mock_client.obtain_certificate.return_value = (mock_cert, 'chain',
                                                       mock_key, 'csr')
        mock_init.return_value = mock_client
        with mock.patch('letsencrypt.cli.OpenSSL'):
            with mock.patch('letsencrypt.cli.crypto_util'):
                self._call(['-d', 'foo.bar', '-a', 'standalone', 'certonly'])
        mock_client.obtain_certificate.assert_called_once_with(['foo.bar'])
        self.assertEqual(mock_lineage.save_successor.call_count, 1)
        mock_lineage.update_all_links_to.assert_called_once_with(
            mock_lineage.latest_common_version())
        self.assertTrue(
            chain_path in mock_get_utility().add_message.call_args[0][0])

    @mock.patch('letsencrypt.crypto_util.notAfter')
    @mock.patch('letsencrypt.cli.display_ops.pick_installer')
    @mock.patch('letsencrypt.cli.zope.component.getUtility')
    @mock.patch('letsencrypt.cli._init_le_client')
    def test_certonly_csr(self, mock_init, mock_get_utility,
                          mock_pick_installer, mock_notAfter):
        cert_path = '/etc/letsencrypt/live/blahcert.pem'
        date = '1970-01-01'
        mock_notAfter().date.return_value = date

        mock_client = mock.MagicMock()
        mock_client.obtain_certificate_from_csr.return_value = ('certr',
                                                                'chain')
        mock_client.save_certificate.return_value = cert_path, None, None
        mock_init.return_value = mock_client

        installer = 'installer'
        self._call(
            ['-a', 'standalone', '-i', installer, 'certonly', '--csr', CSR,
             '--cert-path', cert_path, '--fullchain-path', '/',
             '--chain-path', '/'])
        self.assertEqual(mock_pick_installer.call_args[0][1], installer)
        mock_client.save_certificate.assert_called_once_with(
            'certr', 'chain', cert_path, '/', '/')
        self.assertTrue(
            cert_path in mock_get_utility().add_message.call_args[0][0])
        self.assertTrue(
            date in mock_get_utility().add_message.call_args[0][0])

    @mock.patch('letsencrypt.cli.sys')
    def test_handle_exception(self, mock_sys):
        # pylint: disable=protected-access
        from letsencrypt import cli

        mock_open = mock.mock_open()
        with mock.patch('letsencrypt.cli.open', mock_open, create=True):
            exception = Exception('detail')
            cli._handle_exception(
                Exception, exc_value=exception, trace=None, args=None)
            mock_open().write.assert_called_once_with(''.join(
                traceback.format_exception_only(Exception, exception)))
            error_msg = mock_sys.exit.call_args_list[0][0][0]
            self.assertTrue('unexpected error' in error_msg)

        with mock.patch('letsencrypt.cli.open', mock_open, create=True):
            mock_open.side_effect = [KeyboardInterrupt]
            error = errors.Error('detail')
            cli._handle_exception(
                errors.Error, exc_value=error, trace=None, args=None)
            # assert_any_call used because sys.exit doesn't exit in cli.py
            mock_sys.exit.assert_any_call(''.join(
                traceback.format_exception_only(errors.Error, error)))

        args = mock.MagicMock(debug=False)
        cli._handle_exception(
            Exception, exc_value=Exception('detail'), trace=None, args=args)
        error_msg = mock_sys.exit.call_args_list[-1][0][0]
        self.assertTrue('unexpected error' in error_msg)

        interrupt = KeyboardInterrupt('detail')
        cli._handle_exception(
            KeyboardInterrupt, exc_value=interrupt, trace=None, args=None)
        mock_sys.exit.assert_called_with(''.join(
            traceback.format_exception_only(KeyboardInterrupt, interrupt)))


class DetermineAccountTest(unittest.TestCase):
    """Tests for letsencrypt.cli._determine_account."""

    def setUp(self):
        self.args = mock.MagicMock(account=None, email=None)
        self.config = configuration.NamespaceConfig(self.args)
        self.accs = [mock.MagicMock(id='x'), mock.MagicMock(id='y')]
        self.account_storage = account.AccountMemoryStorage()

    def _call(self):
        # pylint: disable=protected-access
        from letsencrypt.cli import _determine_account
        with mock.patch('letsencrypt.cli.account.AccountFileStorage') as mock_storage:
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

    @mock.patch('letsencrypt.client.display_ops.choose_account')
    def test_multiple_accounts(self, mock_choose_accounts):
        for acc in self.accs:
            self.account_storage.save(acc)
        mock_choose_accounts.return_value = self.accs[1]
        self.assertEqual((self.accs[1], None), self._call())
        self.assertEqual(
            set(mock_choose_accounts.call_args[0][0]), set(self.accs))
        self.assertEqual(self.accs[1].id, self.args.account)
        self.assertTrue(self.args.email is None)

    @mock.patch('letsencrypt.client.display_ops.get_email')
    def test_no_accounts_no_email(self, mock_get_email):
        mock_get_email.return_value = 'foo@bar.baz'

        with mock.patch('letsencrypt.cli.client') as client:
            client.register.return_value = (
                self.accs[0], mock.sentinel.acme)
            self.assertEqual((self.accs[0], mock.sentinel.acme), self._call())
        client.register.assert_called_once_with(
            self.config, self.account_storage, tos_cb=mock.ANY)

        self.assertEqual(self.accs[0].id, self.args.account)
        self.assertEqual('foo@bar.baz', self.args.email)

    def test_no_accounts_email(self):
        self.args.email = 'other email'
        with mock.patch('letsencrypt.cli.client') as client:
            client.register.return_value = (self.accs[1], mock.sentinel.acme)
            self._call()
        self.assertEqual(self.accs[1].id, self.args.account)
        self.assertEqual('other email', self.args.email)


class DuplicativeCertsTest(renewer_test.BaseRenewableCertTest):
    """Test to avoid duplicate lineages."""

    def setUp(self):
        super(DuplicativeCertsTest, self).setUp()
        self.config.write()
        self._write_out_ex_kinds()

    def tearDown(self):
        shutil.rmtree(self.tempdir)

    @mock.patch('letsencrypt.le_util.make_or_verify_dir')
    def test_find_duplicative_names(self, unused_makedir):
        from letsencrypt.cli import _find_duplicative_certs
        test_cert = test_util.load_vector('cert-san.pem')
        with open(self.test_rc.cert, 'w') as f:
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


class MockedVerb(object):
    """Simple class that can be used for mocking out verbs/subcommands.

    Storing a dictionary of verbs and the functions that implement them
    in letsencrypt.cli makes mocking much more complicated. This class
    can be used as a simple context manager for mocking out verbs in CLI
    tests. For example:

    with MockedVerb("run") as mock_run:
        self._call([])
        self.assertEqual(1, mock_run.call_count)

    """
    def __init__(self, verb_name):
        from letsencrypt import cli

        self.verb_dict = cli.HelpfulArgumentParser.VERBS
        self.verb_func = None
        self.verb_name = verb_name

    def __enter__(self):
        self.verb_func = self.verb_dict[self.verb_name]
        mocked_func = mock.MagicMock()
        self.verb_dict[self.verb_name] = mocked_func

        return mocked_func

    def __exit__(self, unused_type, unused_value, unused_trace):
        self.verb_dict[self.verb_name] = self.verb_func


if __name__ == '__main__':
    unittest.main()  # pragma: no cover
