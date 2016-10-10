"""Tests for certbot.cli."""
# Many tests in this file should be moved into
# main_test.py and renewal_test.py. See #2716.
# pylint: disable=too-many-lines
from __future__ import print_function

import argparse
import dialog
import functools
import itertools
import os
import shutil
import traceback
import tempfile
import unittest

import mock
import six
from six.moves import reload_module  # pylint: disable=import-error

from acme import jose

from certbot import account
from certbot import cli
from certbot import configuration
from certbot import constants
from certbot import crypto_util
from certbot import errors
from certbot import util
from certbot import main
from certbot import renewal
from certbot import storage

from certbot.plugins import disco
from certbot.plugins import manual

from certbot.tests import storage_test
from certbot.tests import test_util


CERT = test_util.vector_path('cert.pem')
CSR = test_util.vector_path('csr.der')
KEY = test_util.vector_path('rsa256_key.pem')


class CLITest(unittest.TestCase):  # pylint: disable=too-many-public-methods
    """Tests for different commands."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.config_dir = os.path.join(self.tmp_dir, 'config')
        self.work_dir = os.path.join(self.tmp_dir, 'work')
        self.logs_dir = os.path.join(self.tmp_dir, 'logs')
        self.standard_args = ['--config-dir', self.config_dir,
                              '--work-dir', self.work_dir,
                              '--logs-dir', self.logs_dir, '--text']

    def tearDown(self):
        shutil.rmtree(self.tmp_dir)
        # Reset globals in cli
        # pylint: disable=protected-access
        cli._parser = cli.set_by_cli.detector = None

    def _call(self, args, stdout=None):
        "Run the cli with output streams and actual client mocked out"
        with mock.patch('certbot.main.client') as client:
            ret, stdout, stderr = self._call_no_clientmock(args, stdout)
            return ret, stdout, stderr, client

    def _call_no_clientmock(self, args, stdout=None):
        "Run the client with output streams mocked out"
        args = self.standard_args + args

        toy_stdout = stdout if stdout else six.StringIO()
        with mock.patch('certbot.main.sys.stdout', new=toy_stdout):
            with mock.patch('certbot.main.sys.stderr') as stderr:
                ret = main.main(args[:])  # NOTE: parser can alter its args!
        return ret, toy_stdout, stderr

    def test_no_flags(self):
        with mock.patch('certbot.main.run') as mock_run:
            self._call([])
            self.assertEqual(1, mock_run.call_count)

    def _help_output(self, args):
        "Run a command, and return the ouput string for scrutiny"

        output = six.StringIO()
        self.assertRaises(SystemExit, self._call, args, output)
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
        self.assertTrue("letsencrypt-auto" not in out) # test cli.cli_command
        if "nginx" in plugins:
            self.assertTrue("Use the Nginx plugin" in out)
        else:
            self.assertTrue("(nginx support is experimental" in out)

        out = self._help_output(['--help', 'plugins'])
        self.assertTrue("--manual-test-mode" not in out)
        self.assertTrue("--prepare" in out)
        self.assertTrue('"plugins" subcommand' in out)

        # test multiple topics
        out = self._help_output(['-h', 'renew'])
        self.assertTrue("--keep" in out)
        out = self._help_output(['-h', 'automation'])
        self.assertTrue("--keep" in out)
        out = self._help_output(['-h', 'revoke'])
        self.assertTrue("--keep" not in out)

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
        self.assertTrue(cli.usage_strings(plugins)[0] in out)

    def _cli_missing_flag(self, args, message):
        "Ensure that a particular error raises a missing cli flag error containing message"
        exc = None
        try:
            with mock.patch('certbot.main.sys.stderr'):
                main.main(self.standard_args + args[:])  # NOTE: parser can alter its args!
        except errors.MissingCommandlineFlag as exc_:
            exc = exc_
            self.assertTrue(message in str(exc))
        self.assertTrue(exc is not None)

    def test_noninteractive(self):
        args = ['-n', 'certonly']
        self._cli_missing_flag(args, "specify a plugin")
        args.extend(['--standalone', '-d', 'eg.is'])
        self._cli_missing_flag(args, "register before running")
        with mock.patch('certbot.main._auth_from_domains'):
            with mock.patch('certbot.main.client.acme_from_config_key'):
                args.extend(['--email', 'io@io.is'])
                self._cli_missing_flag(args, "--agree-tos")

    @mock.patch('certbot.main.renew')
    def test_gui(self, renew):
        args = ['renew', '--dialog']
        # --text conflicts with --dialog
        self.standard_args.remove('--text')
        self._call(args)
        self.assertFalse(renew.call_args[0][0].noninteractive_mode)

    @mock.patch('certbot.main.client.acme_client.Client')
    @mock.patch('certbot.main._determine_account')
    @mock.patch('certbot.main.client.Client.obtain_and_enroll_certificate')
    @mock.patch('certbot.main._auth_from_domains')
    def test_user_agent(self, afd, _obt, det, _client):
        # Normally the client is totally mocked out, but here we need more
        # arguments to automate it...
        args = ["--standalone", "certonly", "-m", "none@none.com",
                "-d", "example.com", '--agree-tos'] + self.standard_args
        det.return_value = mock.MagicMock(), None
        afd.return_value = "newcert", mock.MagicMock()

        with mock.patch('certbot.main.client.acme_client.ClientNetwork') as acme_net:
            self._call_no_clientmock(args)
            os_ver = util.get_os_info_ua()
            ua = acme_net.call_args[1]["user_agent"]
            self.assertTrue(os_ver in ua)
            import platform
            plat = platform.platform()
            if "linux" in plat.lower():
                self.assertTrue(util.get_os_info_ua() in ua)

        with mock.patch('certbot.main.client.acme_client.ClientNetwork') as acme_net:
            ua = "bandersnatch"
            args += ["--user-agent", ua]
            self._call_no_clientmock(args)
            acme_net.assert_called_once_with(mock.ANY, verify_ssl=True, user_agent=ua)

    def test_install_abspath(self):
        cert = 'cert'
        key = 'key'
        chain = 'chain'
        fullchain = 'fullchain'

        with mock.patch('certbot.main.install') as mock_install:
            self._call(['install', '--cert-path', cert, '--key-path', 'key',
                        '--chain-path', 'chain',
                        '--fullchain-path', 'fullchain'])

        args = mock_install.call_args[0][0]
        self.assertEqual(args.cert_path, os.path.abspath(cert))
        self.assertEqual(args.key_path, os.path.abspath(key))
        self.assertEqual(args.chain_path, os.path.abspath(chain))
        self.assertEqual(args.fullchain_path, os.path.abspath(fullchain))

    @mock.patch('certbot.main.plug_sel.record_chosen_plugins')
    @mock.patch('certbot.main.plug_sel.pick_installer')
    def test_installer_selection(self, mock_pick_installer, _rec):
        self._call(['install', '--domains', 'foo.bar', '--cert-path', 'cert',
                    '--key-path', 'key', '--chain-path', 'chain'])
        self.assertEqual(mock_pick_installer.call_count, 1)

    @mock.patch('certbot.util.exe_exists')
    def test_configurator_selection(self, mock_exe_exists):
        mock_exe_exists.return_value = True
        real_plugins = disco.PluginsRegistry.find_all()
        args = ['--apache', '--authenticator', 'standalone']

        # This needed two calls to find_all(), which we're avoiding for now
        # because of possible side effects:
        # https://github.com/letsencrypt/letsencrypt/commit/51ed2b681f87b1eb29088dd48718a54f401e4855
        #with mock.patch('certbot.cli.plugins_testable') as plugins:
        #    plugins.return_value = {"apache": True, "nginx": True}
        #    ret, _, _, _ = self._call(args)
        #    self.assertTrue("Too many flags setting" in ret)

        args = ["install", "--nginx", "--cert-path", "/tmp/blah", "--key-path", "/tmp/blah",
                "--nginx-server-root", "/nonexistent/thing", "-d",
                "example.com", "--debug"]
        if "nginx" in real_plugins:
            # Sending nginx a non-existent conf dir will simulate misconfiguration
            # (we can only do that if certbot-nginx is actually present)
            ret, _, _, _ = self._call(args)
            self.assertTrue("The nginx plugin is not working" in ret)
            self.assertTrue("MisconfigurationError" in ret)

        self._cli_missing_flag(["--standalone"], "With the standalone plugin, you probably")

        with mock.patch("certbot.main._init_le_client") as mock_init:
            with mock.patch("certbot.main._auth_from_domains") as mock_afd:
                mock_afd.return_value = (mock.MagicMock(), mock.MagicMock())
                self._call(["certonly", "--manual", "-d", "foo.bar"])
                unused_config, auth, unused_installer = mock_init.call_args[0]
                self.assertTrue(isinstance(auth, manual.Authenticator))

        with mock.patch('certbot.main.obtain_cert') as mock_certonly:
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
                  for r in six.moves.range(len(flags)))):
            self._call(['plugins'] + list(args))

    @mock.patch('certbot.main.plugins_disco')
    @mock.patch('certbot.main.cli.HelpfulArgumentParser.determine_help_topics')
    def test_plugins_no_args(self, _det, mock_disco):
        ifaces = []
        plugins = mock_disco.PluginsRegistry.find_all()

        _, stdout, _, _ = self._call(['plugins'])
        plugins.visible.assert_called_once_with()
        plugins.visible().ifaces.assert_called_once_with(ifaces)
        filtered = plugins.visible().ifaces()
        self.assertEqual(stdout.getvalue().strip(), str(filtered))

    @mock.patch('certbot.main.plugins_disco')
    @mock.patch('certbot.main.cli.HelpfulArgumentParser.determine_help_topics')
    def test_plugins_init(self, _det, mock_disco):
        ifaces = []
        plugins = mock_disco.PluginsRegistry.find_all()

        _, stdout, _, _ = self._call(['plugins', '--init'])
        plugins.visible.assert_called_once_with()
        plugins.visible().ifaces.assert_called_once_with(ifaces)
        filtered = plugins.visible().ifaces()
        self.assertEqual(filtered.init.call_count, 1)
        filtered.verify.assert_called_once_with(ifaces)
        verified = filtered.verify()
        self.assertEqual(stdout.getvalue().strip(), str(verified))

    @mock.patch('certbot.main.plugins_disco')
    @mock.patch('certbot.main.cli.HelpfulArgumentParser.determine_help_topics')
    def test_plugins_prepare(self, _det, mock_disco):
        ifaces = []
        plugins = mock_disco.PluginsRegistry.find_all()
        _, stdout, _, _ = self._call(['plugins', '--init', '--prepare'])
        plugins.visible.assert_called_once_with()
        plugins.visible().ifaces.assert_called_once_with(ifaces)
        filtered = plugins.visible().ifaces()
        self.assertEqual(filtered.init.call_count, 1)
        filtered.verify.assert_called_once_with(ifaces)
        verified = filtered.verify()
        verified.prepare.assert_called_once_with()
        verified.available.assert_called_once_with()
        available = verified.available()
        self.assertEqual(stdout.getvalue().strip(), str(available))

    def test_certonly_abspath(self):
        cert = 'cert'
        key = 'key'
        chain = 'chain'
        fullchain = 'fullchain'

        with mock.patch('certbot.main.obtain_cert') as mock_obtaincert:
            self._call(['certonly', '--cert-path', cert, '--key-path', 'key',
                        '--chain-path', 'chain',
                        '--fullchain-path', 'fullchain'])

        config, unused_plugins = mock_obtaincert.call_args[0]
        self.assertEqual(config.cert_path, os.path.abspath(cert))
        self.assertEqual(config.key_path, os.path.abspath(key))
        self.assertEqual(config.chain_path, os.path.abspath(chain))
        self.assertEqual(config.fullchain_path, os.path.abspath(fullchain))

    def test_certonly_bad_args(self):
        try:
            self._call(['-a', 'bad_auth', 'certonly'])
            assert False, "Exception should have been raised"
        except errors.PluginSelectionError as e:
            self.assertTrue('The requested bad_auth plugin does not appear' in str(e))

    def test_check_config_sanity_domain(self):
        # Punycode
        self.assertRaises(errors.ConfigurationError,
                          self._call,
                          ['-d', 'this.is.xn--ls8h.tld'])
        # FQDN
        self.assertRaises(errors.ConfigurationError,
                          self._call,
                          ['-d', 'a' * 64])
        # FQDN 2
        self.assertRaises(errors.ConfigurationError,
                          self._call,
                          ['-d', (('a' * 50) + '.') * 10])
        # Wildcard
        self.assertRaises(errors.ConfigurationError,
                          self._call,
                          ['-d', '*.wildcard.tld'])

        # Bare IP address (this is actually a different error message now)
        self.assertRaises(errors.ConfigurationError,
                          self._call,
                          ['-d', '204.11.231.35'])

    def test_csr_with_besteffort(self):
        self.assertRaises(
            errors.Error, self._call,
            'certonly --csr {0} --allow-subset-of-names'.format(CSR).split())

    def test_run_with_csr(self):
        # This is an error because you can only use --csr with certonly
        try:
            self._call(['--csr', CSR])
        except errors.Error as e:
            assert "Please try the certonly" in repr(e)
            return
        assert False, "Expected supplying --csr to fail with default verb"

    def test_csr_with_no_domains(self):
        self.assertRaises(
            errors.Error, self._call,
            'certonly --csr {0}'.format(
                test_util.vector_path('csr-nonames.pem')).split())

    def test_csr_with_inconsistent_domains(self):
        self.assertRaises(
            errors.Error, self._call,
            'certonly -d example.org --csr {0}'.format(CSR).split())

    def _get_argument_parser(self):
        plugins = disco.PluginsRegistry.find_all()
        return functools.partial(cli.prepare_and_parse_args, plugins)

    def test_parse_domains(self):
        parse = self._get_argument_parser()

        short_args = ['-d', 'example.com']
        namespace = parse(short_args)
        self.assertEqual(namespace.domains, ['example.com'])

        short_args = ['-d', 'trailing.period.com.']
        namespace = parse(short_args)
        self.assertEqual(namespace.domains, ['trailing.period.com'])

        short_args = ['-d', 'example.com,another.net,third.org,example.com']
        namespace = parse(short_args)
        self.assertEqual(namespace.domains, ['example.com', 'another.net',
                                             'third.org'])

        long_args = ['--domains', 'example.com']
        namespace = parse(long_args)
        self.assertEqual(namespace.domains, ['example.com'])

        long_args = ['--domains', 'trailing.period.com.']
        namespace = parse(long_args)
        self.assertEqual(namespace.domains, ['trailing.period.com'])

        long_args = ['--domains', 'example.com,another.net,example.com']
        namespace = parse(long_args)
        self.assertEqual(namespace.domains, ['example.com', 'another.net'])

    def test_preferred_challenges(self):
        from acme.challenges import HTTP01, TLSSNI01, DNS01
        parse = self._get_argument_parser()

        short_args = ['--preferred-challenges', 'http, tls-sni-01, dns']
        namespace = parse(short_args)

        self.assertEqual(namespace.pref_challs, [HTTP01, TLSSNI01, DNS01])

        short_args = ['--preferred-challenges', 'jumping-over-the-moon']
        self.assertRaises(argparse.ArgumentTypeError, parse, short_args)

    def test_server_flag(self):
        parse = self._get_argument_parser()
        namespace = parse('--server example.com'.split())
        self.assertEqual(namespace.server, 'example.com')

    def _check_server_conflict_message(self, parser_args, conflicting_args):
        parse = self._get_argument_parser()
        try:
            parse(parser_args)
            self.fail(  # pragma: no cover
                "The following flags didn't conflict with "
                '--server: {0}'.format(', '.join(conflicting_args)))
        except errors.Error as error:
            self.assertTrue('--server' in str(error))
            for arg in conflicting_args:
                self.assertTrue(arg in str(error))

    def test_must_staple_flag(self):
        parse = self._get_argument_parser()
        short_args = ['--must-staple']
        namespace = parse(short_args)
        self.assertTrue(namespace.must_staple)
        self.assertTrue(namespace.staple)

    def test_staging_flag(self):
        parse = self._get_argument_parser()
        short_args = ['--staging']
        namespace = parse(short_args)
        self.assertTrue(namespace.staging)
        self.assertEqual(namespace.server, constants.STAGING_URI)

        short_args += '--server example.com'.split()
        self._check_server_conflict_message(short_args, '--staging')

    def test_option_was_set(self):
        key_size_option = 'rsa_key_size'
        key_size_value = cli.flag_default(key_size_option)
        self._get_argument_parser()(
            '--rsa-key-size {0}'.format(key_size_value).split())

        self.assertTrue(cli.option_was_set(key_size_option, key_size_value))
        self.assertTrue(cli.option_was_set('no_verify_ssl', True))

        config_dir_option = 'config_dir'
        self.assertFalse(cli.option_was_set(
            config_dir_option, cli.flag_default(config_dir_option)))

    def _assert_dry_run_flag_worked(self, namespace, existing_account):
        self.assertTrue(namespace.dry_run)
        self.assertTrue(namespace.break_my_certs)
        self.assertTrue(namespace.staging)
        self.assertEqual(namespace.server, constants.STAGING_URI)

        if existing_account:
            self.assertTrue(namespace.tos)
            self.assertTrue(namespace.register_unsafely_without_email)
        else:
            self.assertFalse(namespace.tos)
            self.assertFalse(namespace.register_unsafely_without_email)

    def test_dry_run_flag(self):
        parse = self._get_argument_parser()
        config_dir = tempfile.mkdtemp()
        short_args = '--dry-run --config-dir {0}'.format(config_dir).split()
        self.assertRaises(errors.Error, parse, short_args)

        self._assert_dry_run_flag_worked(
            parse(short_args + ['auth']), False)
        self._assert_dry_run_flag_worked(
            parse(short_args + ['certonly']), False)
        self._assert_dry_run_flag_worked(
            parse(short_args + ['renew']), False)

        account_dir = os.path.join(config_dir, constants.ACCOUNTS_DIR)
        os.mkdir(account_dir)
        os.mkdir(os.path.join(account_dir, 'fake_account_dir'))

        self._assert_dry_run_flag_worked(parse(short_args + ['auth']), True)
        self._assert_dry_run_flag_worked(parse(short_args + ['renew']), True)
        short_args += ['certonly']
        self._assert_dry_run_flag_worked(parse(short_args), True)

        short_args += '--server example.com'.split()
        conflicts = ['--dry-run']
        self._check_server_conflict_message(short_args, '--dry-run')

        short_args += ['--staging']
        conflicts += ['--staging']
        self._check_server_conflict_message(short_args, conflicts)

    def _certonly_new_request_common(self, mock_client, args=None):
        with mock.patch('certbot.main._treat_as_renewal') as mock_renewal:
            mock_renewal.return_value = ("newcert", None)
            with mock.patch('certbot.main._init_le_client') as mock_init:
                mock_init.return_value = mock_client
                if args is None:
                    args = []
                args += '-d foo.bar -a standalone certonly'.split()
                self._call(args)

    @mock.patch('certbot.main.zope.component.getUtility')
    def test_certonly_dry_run_new_request_success(self, mock_get_utility):
        mock_client = mock.MagicMock()
        mock_client.obtain_and_enroll_certificate.return_value = None
        self._certonly_new_request_common(mock_client, ['--dry-run'])
        self.assertEqual(
            mock_client.obtain_and_enroll_certificate.call_count, 1)
        self.assertTrue(
            'dry run' in mock_get_utility().add_message.call_args[0][0])
        # Asserts we don't suggest donating after a successful dry run
        self.assertEqual(mock_get_utility().add_message.call_count, 1)

    @mock.patch('certbot.crypto_util.notAfter')
    @mock.patch('certbot.main.zope.component.getUtility')
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
        cert_msg = mock_get_utility().add_message.call_args_list[0][0][0]
        self.assertTrue(cert_path in cert_msg)
        self.assertTrue(date in cert_msg)
        self.assertTrue(
            'donate' in mock_get_utility().add_message.call_args[0][0])

    def test_certonly_new_request_failure(self):
        mock_client = mock.MagicMock()
        mock_client.obtain_and_enroll_certificate.return_value = False
        self.assertRaises(errors.Error,
                          self._certonly_new_request_common, mock_client)

    def _test_renewal_common(self, due_for_renewal, extra_args, log_out=None,
                             args=None, should_renew=True, error_expected=False):
        # pylint: disable=too-many-locals,too-many-arguments
        cert_path = test_util.vector_path('cert.pem')
        chain_path = '/etc/letsencrypt/live/foo.bar/fullchain.pem'
        mock_lineage = mock.MagicMock(cert=cert_path, fullchain=chain_path)
        mock_lineage.should_autorenew.return_value = due_for_renewal
        mock_lineage.has_pending_deployment.return_value = False
        mock_certr = mock.MagicMock()
        mock_key = mock.MagicMock(pem='pem_key')
        mock_client = mock.MagicMock()
        stdout = None
        mock_client.obtain_certificate.return_value = (mock_certr, 'chain',
                                                       mock_key, 'csr')
        try:
            with mock.patch('certbot.main._find_duplicative_certs') as mock_fdc:
                mock_fdc.return_value = (mock_lineage, None)
                with mock.patch('certbot.main._init_le_client') as mock_init:
                    mock_init.return_value = mock_client
                    get_utility_path = 'certbot.main.zope.component.getUtility'
                    with mock.patch(get_utility_path) as mock_get_utility:
                        with mock.patch('certbot.main.renewal.OpenSSL') as mock_ssl:
                            mock_latest = mock.MagicMock()
                            mock_latest.get_issuer.return_value = "Fake fake"
                            mock_ssl.crypto.load_certificate.return_value = mock_latest
                            with mock.patch('certbot.main.renewal.crypto_util'):
                                if not args:
                                    args = ['-d', 'isnot.org', '-a', 'standalone', 'certonly']
                                if extra_args:
                                    args += extra_args
                                try:
                                    ret, stdout, _, _ = self._call(args)
                                    if ret:
                                        print("Returned", ret)
                                        raise AssertionError(ret)
                                    assert not error_expected, "renewal should have errored"
                                except: # pylint: disable=bare-except
                                    if not error_expected:
                                        raise AssertionError(
                                            "Unexpected renewal error:\n" +
                                            traceback.format_exc())

            if should_renew:
                mock_client.obtain_certificate.assert_called_once_with(['isnot.org'])
            else:
                self.assertEqual(mock_client.obtain_certificate.call_count, 0)
        except:
            self._dump_log()
            raise
        finally:
            if log_out:
                with open(os.path.join(self.logs_dir, "letsencrypt.log")) as lf:
                    self.assertTrue(log_out in lf.read())

        return mock_lineage, mock_get_utility, stdout

    def test_certonly_renewal(self):
        lineage, get_utility, _ = self._test_renewal_common(True, [])
        self.assertEqual(lineage.save_successor.call_count, 1)
        lineage.update_all_links_to.assert_called_once_with(
            lineage.latest_common_version())
        cert_msg = get_utility().add_message.call_args_list[0][0][0]
        self.assertTrue('fullchain.pem' in cert_msg)
        self.assertTrue('donate' in get_utility().add_message.call_args[0][0])

    def test_certonly_renewal_triggers(self):
        # --dry-run should force renewal
        _, get_utility, _ = self._test_renewal_common(False, ['--dry-run', '--keep'],
                                                      log_out="simulating renewal")
        self.assertEqual(get_utility().add_message.call_count, 1)
        self.assertTrue('dry run' in get_utility().add_message.call_args[0][0])

        self._test_renewal_common(False, ['--renew-by-default', '-tvv', '--debug'],
                                  log_out="Auto-renewal forced")
        self.assertEqual(get_utility().add_message.call_count, 1)

        self._test_renewal_common(False, ['-tvv', '--debug', '--keep'],
                                  log_out="not yet due", should_renew=False)

    def _dump_log(self):
        with open(os.path.join(self.logs_dir, "letsencrypt.log")) as lf:
            print("Logs:")
            print(lf.read())

    def _make_lineage(self, testfile):
        """Creates a lineage defined by testfile.

        This creates the archive, live, and renewal directories if
        necessary and creates a simple lineage.

        :param str testfile: configuration file to base the lineage on

        :returns: path to the renewal conf file for the created lineage
        :rtype: str

        """
        lineage_name = testfile[:-len('.conf')]

        conf_dir = os.path.join(
            self.config_dir, constants.RENEWAL_CONFIGS_DIR)
        archive_dir = os.path.join(
            self.config_dir, constants.ARCHIVE_DIR, lineage_name)
        live_dir = os.path.join(
            self.config_dir, constants.LIVE_DIR, lineage_name)

        for directory in (archive_dir, conf_dir, live_dir,):
            if not os.path.exists(directory):
                os.makedirs(directory)

        sample_archive = test_util.vector_path('sample-archive')
        for kind in os.listdir(sample_archive):
            shutil.copyfile(os.path.join(sample_archive, kind),
                            os.path.join(archive_dir, kind))

        for kind in storage.ALL_FOUR:
            os.symlink(os.path.join(archive_dir, '{0}1.pem'.format(kind)),
                       os.path.join(live_dir, '{0}.pem'.format(kind)))

        conf_path = os.path.join(self.config_dir, conf_dir, testfile)
        with open(test_util.vector_path(testfile)) as src:
            with open(conf_path, 'w') as dst:
                dst.writelines(
                    line.replace('MAGICDIR', self.config_dir) for line in src)

        return conf_path

    def test_renew_verb(self):
        self._make_lineage('sample-renewal.conf')
        args = ["renew", "--dry-run", "-tvv"]
        self._test_renewal_common(True, [], args=args, should_renew=True)

    def test_quiet_renew(self):
        self._make_lineage('sample-renewal.conf')
        args = ["renew", "--dry-run"]
        _, _, stdout = self._test_renewal_common(True, [], args=args, should_renew=True)
        out = stdout.getvalue()
        self.assertTrue("renew" in out)

        args = ["renew", "--dry-run", "-q"]
        _, _, stdout = self._test_renewal_common(True, [], args=args, should_renew=True)
        out = stdout.getvalue()
        self.assertEqual("", out)

    def test_renew_hook_validation(self):
        self._make_lineage('sample-renewal.conf')
        args = ["renew", "--dry-run", "--post-hook=no-such-command"]
        self._test_renewal_common(True, [], args=args, should_renew=False,
                                  error_expected=True)

    def test_renew_no_hook_validation(self):
        self._make_lineage('sample-renewal.conf')
        args = ["renew", "--dry-run", "--post-hook=no-such-command",
                "--disable-hook-validation"]
        self._test_renewal_common(True, [], args=args, should_renew=True,
                                  error_expected=False)

    @mock.patch("certbot.cli.set_by_cli")
    def test_ancient_webroot_renewal_conf(self, mock_set_by_cli):
        mock_set_by_cli.return_value = False
        rc_path = self._make_lineage('sample-renewal-ancient.conf')
        args = mock.MagicMock(account=None, email=None, webroot_path=None)
        config = configuration.NamespaceConfig(args)
        lineage = storage.RenewableCert(rc_path,
            configuration.RenewerConfiguration(config))
        renewalparams = lineage.configuration["renewalparams"]
        # pylint: disable=protected-access
        renewal._restore_webroot_config(config, renewalparams)
        self.assertEqual(config.webroot_path, ["/var/www/"])

    def test_renew_verb_empty_config(self):
        rd = os.path.join(self.config_dir, 'renewal')
        if not os.path.exists(rd):
            os.makedirs(rd)
        with open(os.path.join(rd, 'empty.conf'), 'w'):
            pass  # leave the file empty
        args = ["renew", "--dry-run", "-tvv"]
        self._test_renewal_common(False, [], args=args, should_renew=False, error_expected=True)

    def _make_dummy_renewal_config(self):
        renewer_configs_dir = os.path.join(self.config_dir, 'renewal')
        os.makedirs(renewer_configs_dir)
        with open(os.path.join(renewer_configs_dir, 'test.conf'), 'w') as f:
            f.write("My contents don't matter")

    def _test_renew_common(self, renewalparams=None, names=None,
                           assert_oc_called=None, **kwargs):
        self._make_dummy_renewal_config()
        with mock.patch('certbot.storage.RenewableCert') as mock_rc:
            mock_lineage = mock.MagicMock()
            mock_lineage.fullchain = "somepath/fullchain.pem"
            if renewalparams is not None:
                mock_lineage.configuration = {'renewalparams': renewalparams}
            if names is not None:
                mock_lineage.names.return_value = names
            mock_rc.return_value = mock_lineage
            with mock.patch('certbot.main.obtain_cert') as mock_obtain_cert:
                kwargs.setdefault('args', ['renew'])
                self._test_renewal_common(True, None, should_renew=False, **kwargs)

            if assert_oc_called is not None:
                if assert_oc_called:
                    self.assertTrue(mock_obtain_cert.called)
                else:
                    self.assertFalse(mock_obtain_cert.called)

    def test_renew_no_renewalparams(self):
        self._test_renew_common(assert_oc_called=False, error_expected=True)

    def test_renew_no_authenticator(self):
        self._test_renew_common(renewalparams={}, assert_oc_called=False,
            error_expected=True)

    def test_renew_with_bad_int(self):
        renewalparams = {'authenticator': 'webroot',
                         'rsa_key_size': 'over 9000'}
        self._test_renew_common(renewalparams=renewalparams, error_expected=True,
                                assert_oc_called=False)

    def test_renew_with_nonetype_http01(self):
        renewalparams = {'authenticator': 'webroot',
                         'http01_port': 'None'}
        self._test_renew_common(renewalparams=renewalparams,
                                assert_oc_called=True)

    def test_renew_with_bad_domain(self):
        renewalparams = {'authenticator': 'webroot'}
        names = ['*.example.com']
        self._test_renew_common(renewalparams=renewalparams, error_expected=True,
                                names=names, assert_oc_called=False)

    def test_renew_with_configurator(self):
        renewalparams = {'authenticator': 'webroot'}
        self._test_renew_common(
            renewalparams=renewalparams, assert_oc_called=True,
            args='renew --configurator apache'.split())

    def test_renew_plugin_config_restoration(self):
        renewalparams = {'authenticator': 'webroot',
                         'webroot_path': 'None',
                         'webroot_imaginary_flag': '42'}
        self._test_renew_common(renewalparams=renewalparams,
                                assert_oc_called=True)

    def test_renew_with_webroot_map(self):
        renewalparams = {'authenticator': 'webroot'}
        self._test_renew_common(
            renewalparams=renewalparams, assert_oc_called=True,
            args=['renew', '--webroot-map', '{"example.com": "/tmp"}'])

    def test_renew_reconstitute_error(self):
        # pylint: disable=protected-access
        with mock.patch('certbot.main.renewal._reconstitute') as mock_reconstitute:
            mock_reconstitute.side_effect = Exception
            self._test_renew_common(assert_oc_called=False, error_expected=True)

    def test_renew_obtain_cert_error(self):
        self._make_dummy_renewal_config()
        with mock.patch('certbot.storage.RenewableCert') as mock_rc:
            mock_lineage = mock.MagicMock()
            mock_lineage.fullchain = "somewhere/fullchain.pem"
            mock_rc.return_value = mock_lineage
            mock_lineage.configuration = {
                'renewalparams': {'authenticator': 'webroot'}}
            with mock.patch('certbot.main.obtain_cert') as mock_obtain_cert:
                mock_obtain_cert.side_effect = Exception
                self._test_renewal_common(True, None, error_expected=True,
                                          args=['renew'], should_renew=False)

    def test_renew_with_bad_cli_args(self):
        self._test_renewal_common(True, None, args='renew -d example.com'.split(),
                                  should_renew=False, error_expected=True)
        self._test_renewal_common(True, None, args='renew --csr {0}'.format(CSR).split(),
                                  should_renew=False, error_expected=True)

    @mock.patch('certbot.main.zope.component.getUtility')
    @mock.patch('certbot.main._treat_as_renewal')
    @mock.patch('certbot.main._init_le_client')
    def test_certonly_reinstall(self, mock_init, mock_renewal, mock_get_utility):
        mock_renewal.return_value = ('reinstall', mock.MagicMock())
        mock_init.return_value = mock_client = mock.MagicMock()
        self._call(['-d', 'foo.bar', '-a', 'standalone', 'certonly'])
        self.assertFalse(mock_client.obtain_certificate.called)
        self.assertFalse(mock_client.obtain_and_enroll_certificate.called)
        self.assertEqual(mock_get_utility().add_message.call_count, 0)
        #self.assertTrue('donate' not in mock_get_utility().add_message.call_args[0][0])

    def _test_certonly_csr_common(self, extra_args=None):
        certr = 'certr'
        chain = 'chain'
        mock_client = mock.MagicMock()
        mock_client.obtain_certificate_from_csr.return_value = (certr, chain)
        cert_path = '/etc/letsencrypt/live/example.com/cert.pem'
        mock_client.save_certificate.return_value = cert_path, None, None
        with mock.patch('certbot.main._init_le_client') as mock_init:
            mock_init.return_value = mock_client
            get_utility_path = 'certbot.main.zope.component.getUtility'
            with mock.patch(get_utility_path) as mock_get_utility:
                chain_path = '/etc/letsencrypt/live/example.com/chain.pem'
                full_path = '/etc/letsencrypt/live/example.com/fullchain.pem'
                args = ('-a standalone certonly --csr {0} --cert-path {1} '
                        '--chain-path {2} --fullchain-path {3}').format(
                            CSR, cert_path, chain_path, full_path).split()
                if extra_args:
                    args += extra_args
                with mock.patch('certbot.main.crypto_util'):
                    self._call(args)

        if '--dry-run' in args:
            self.assertFalse(mock_client.save_certificate.called)
        else:
            mock_client.save_certificate.assert_called_once_with(
                certr, chain, cert_path, chain_path, full_path)

        return mock_get_utility

    def test_certonly_csr(self):
        mock_get_utility = self._test_certonly_csr_common()
        cert_msg = mock_get_utility().add_message.call_args_list[0][0][0]
        self.assertTrue('cert.pem' in cert_msg)
        self.assertTrue(
            'donate' in mock_get_utility().add_message.call_args[0][0])

    def test_certonly_csr_dry_run(self):
        mock_get_utility = self._test_certonly_csr_common(['--dry-run'])
        self.assertEqual(mock_get_utility().add_message.call_count, 1)
        self.assertTrue(
            'dry run' in mock_get_utility().add_message.call_args[0][0])

    @mock.patch('certbot.main.client.acme_client')
    def test_revoke_with_key(self, mock_acme_client):
        server = 'foo.bar'
        self._call_no_clientmock(['--cert-path', CERT, '--key-path', KEY,
                                 '--server', server, 'revoke'])
        with open(KEY, 'rb') as f:
            mock_acme_client.Client.assert_called_once_with(
                server, key=jose.JWK.load(f.read()), net=mock.ANY)
        with open(CERT, 'rb') as f:
            cert = crypto_util.pyopenssl_load_certificate(f.read())[0]
            mock_revoke = mock_acme_client.Client().revoke
            mock_revoke.assert_called_once_with(jose.ComparableX509(cert))

    @mock.patch('certbot.main._determine_account')
    def test_revoke_without_key(self, mock_determine_account):
        mock_determine_account.return_value = (mock.MagicMock(), None)
        _, _, _, client = self._call(['--cert-path', CERT, 'revoke'])
        with open(CERT) as f:
            cert = crypto_util.pyopenssl_load_certificate(f.read())[0]
            mock_revoke = client.acme_from_config_key().revoke
            mock_revoke.assert_called_once_with(jose.ComparableX509(cert))

    @mock.patch('certbot.main.sys')
    def test_handle_exception(self, mock_sys):
        # pylint: disable=protected-access
        from acme import messages

        config = mock.MagicMock()
        mock_open = mock.mock_open()

        with mock.patch('certbot.main.open', mock_open, create=True):
            exception = Exception('detail')
            config.verbose_count = 1
            main._handle_exception(
                Exception, exc_value=exception, trace=None, config=None)
            mock_open().write.assert_any_call(''.join(
                traceback.format_exception_only(Exception, exception)))
            error_msg = mock_sys.exit.call_args_list[0][0][0]
            self.assertTrue('unexpected error' in error_msg)

        with mock.patch('certbot.main.open', mock_open, create=True):
            mock_open.side_effect = [KeyboardInterrupt]
            error = errors.Error('detail')
            main._handle_exception(
                errors.Error, exc_value=error, trace=None, config=None)
            # assert_any_call used because sys.exit doesn't exit in cli.py
            mock_sys.exit.assert_any_call(''.join(
                traceback.format_exception_only(errors.Error, error)))

        exception = messages.Error(detail='alpha', typ='urn:acme:error:triffid',
                                   title='beta')
        config = mock.MagicMock(debug=False, verbose_count=-3)
        main._handle_exception(
            messages.Error, exc_value=exception, trace=None, config=config)
        error_msg = mock_sys.exit.call_args_list[-1][0][0]
        self.assertTrue('unexpected error' in error_msg)
        self.assertTrue('acme:error' not in error_msg)
        self.assertTrue('alpha' in error_msg)
        self.assertTrue('beta' in error_msg)
        config = mock.MagicMock(debug=False, verbose_count=1)
        main._handle_exception(
            messages.Error, exc_value=exception, trace=None, config=config)
        error_msg = mock_sys.exit.call_args_list[-1][0][0]
        self.assertTrue('unexpected error' in error_msg)
        self.assertTrue('acme:error' in error_msg)
        self.assertTrue('alpha' in error_msg)

        interrupt = KeyboardInterrupt('detail')
        main._handle_exception(
            KeyboardInterrupt, exc_value=interrupt, trace=None, config=None)
        mock_sys.exit.assert_called_with(''.join(
            traceback.format_exception_only(KeyboardInterrupt, interrupt)))

        # Test dialog errors
        exception = dialog.error(message="test message")
        main._handle_exception(
                dialog.DialogError, exc_value=exception, trace=None, config=None)
        error_msg = mock_sys.exit.call_args_list[-1][0][0]
        self.assertTrue("test message" in error_msg)

    def test_read_file(self):
        rel_test_path = os.path.relpath(os.path.join(self.tmp_dir, 'foo'))
        self.assertRaises(
            argparse.ArgumentTypeError, cli.read_file, rel_test_path)

        test_contents = b'bar\n'
        with open(rel_test_path, 'wb') as f:
            f.write(test_contents)

        path, contents = cli.read_file(rel_test_path)
        self.assertEqual(path, os.path.abspath(path))
        self.assertEqual(contents, test_contents)

    def test_agree_dev_preview_config(self):
        with mock.patch('certbot.main.run') as mocked_run:
            self._call(['-c', test_util.vector_path('cli.ini')])
        self.assertTrue(mocked_run.called)

    def test_register(self):
        with mock.patch('certbot.main.client') as mocked_client:
            acc = mock.MagicMock()
            acc.id = "imaginary_account"
            mocked_client.register.return_value = (acc, "worked")
            self._call_no_clientmock(["register", "--email", "user@example.org"])
            # TODO: It would be more correct to explicitly check that
            #       _determine_account() gets called in the above case,
            #       but coverage statistics should also show that it did.
            with mock.patch('certbot.main.account') as mocked_account:
                mocked_storage = mock.MagicMock()
                mocked_account.AccountFileStorage.return_value = mocked_storage
                mocked_storage.find_all.return_value = ["an account"]
                x = self._call_no_clientmock(["register", "--email", "user@example.org"])
                self.assertTrue("There is an existing account" in x[0])

    def test_update_registration_no_existing_accounts(self):
        # with mock.patch('certbot.main.client') as mocked_client:
        with mock.patch('certbot.main.account') as mocked_account:
            mocked_storage = mock.MagicMock()
            mocked_account.AccountFileStorage.return_value = mocked_storage
            mocked_storage.find_all.return_value = []
            x = self._call_no_clientmock(
                ["register", "--update-registration", "--email",
                 "user@example.org"])
            self.assertTrue("Could not find an existing account" in x[0])

    def test_update_registration_unsafely(self):
        # This test will become obsolete when register --update-registration
        # supports removing an e-mail address from the account
        with mock.patch('certbot.main.account') as mocked_account:
            mocked_storage = mock.MagicMock()
            mocked_account.AccountFileStorage.return_value = mocked_storage
            mocked_storage.find_all.return_value = ["an account"]
            x = self._call_no_clientmock(
                "register --update-registration "
                "--register-unsafely-without-email".split())
            self.assertTrue("--register-unsafely-without-email" in x[0])

    @mock.patch('certbot.main.display_ops.get_email')
    @mock.patch('certbot.main.zope.component.getUtility')
    def test_update_registration_with_email(self, mock_utility, mock_email):
        email = "user@example.com"
        mock_email.return_value = email
        with mock.patch('certbot.main.client') as mocked_client:
            with mock.patch('certbot.main.account') as mocked_account:
                with mock.patch('certbot.main._determine_account') as mocked_det:
                    with mock.patch('certbot.main.client') as mocked_client:
                        mocked_storage = mock.MagicMock()
                        mocked_account.AccountFileStorage.return_value = mocked_storage
                        mocked_storage.find_all.return_value = ["an account"]
                        mocked_det.return_value = (mock.MagicMock(), "foo")
                        acme_client = mock.MagicMock()
                        mocked_client.Client.return_value = acme_client
                        x = self._call_no_clientmock(
                            ["register", "--update-registration"])
                        # When registration change succeeds, the return value
                        # of register() is None
                        self.assertTrue(x[0] is None)
                        # and we got supposedly did update the registration from
                        # the server
                        self.assertTrue(
                            acme_client.acme.update_registration.called)
                        # and we saved the updated registration on disk
                        self.assertTrue(mocked_storage.save_regr.called)
                        self.assertTrue(
                            email in mock_utility().add_message.call_args[0][0])

    def test_conflicting_args(self):
        args = ['renew', '--dialog', '--text']
        self.assertRaises(errors.Error, self._call, args)

    def test_text_mode_when_verbose(self):
        parse = self._get_argument_parser()
        short_args = ['-v']
        namespace = parse(short_args)
        self.assertTrue(namespace.text_mode)


class DetermineAccountTest(unittest.TestCase):
    """Tests for certbot.cli._determine_account."""

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


class DefaultTest(unittest.TestCase):
    """Tests for certbot.cli._Default."""

    def setUp(self):
        # pylint: disable=protected-access
        self.default1 = cli._Default()
        self.default2 = cli._Default()

    def test_boolean(self):
        self.assertFalse(self.default1)
        self.assertFalse(self.default2)

    def test_equality(self):
        self.assertEqual(self.default1, self.default2)

    def test_hash(self):
        self.assertEqual(hash(self.default1), hash(self.default2))


class SetByCliTest(unittest.TestCase):
    """Tests for certbot.set_by_cli and related functions."""

    def setUp(self):
        reload_module(cli)

    def test_webroot_map(self):
        args = '-w /var/www/html -d example.com'.split()
        verb = 'renew'
        self.assertTrue(_call_set_by_cli('webroot_map', args, verb))

    def test_report_config_interaction_str(self):
        cli.report_config_interaction('manual_public_ip_logging_ok',
                                      'manual_test_mode')
        cli.report_config_interaction('manual_test_mode', 'manual')

        self._test_report_config_interaction_common()

    def test_report_config_interaction_iterable(self):
        cli.report_config_interaction(('manual_public_ip_logging_ok',),
                                      ('manual_test_mode',))
        cli.report_config_interaction(('manual_test_mode',), ('manual',))

        self._test_report_config_interaction_common()

    def _test_report_config_interaction_common(self):
        """Tests implied interaction between manual flags.

        --manual implies --manual-test-mode which implies
        --manual-public-ip-logging-ok. These interactions don't actually
        exist in the client, but are used here for testing purposes.

        """

        args = ['--manual']
        verb = 'renew'
        for v in ('manual', 'manual_test_mode', 'manual_public_ip_logging_ok'):
            self.assertTrue(_call_set_by_cli(v, args, verb))

        cli.set_by_cli.detector = None

        args = ['--manual-test-mode']
        for v in ('manual_test_mode', 'manual_public_ip_logging_ok'):
            self.assertTrue(_call_set_by_cli(v, args, verb))

        self.assertFalse(_call_set_by_cli('manual', args, verb))


def _call_set_by_cli(var, args, verb):
    with mock.patch('certbot.cli.helpful_parser') as mock_parser:
        mock_parser.args = args
        mock_parser.verb = verb
        return cli.set_by_cli(var)


if __name__ == '__main__':
    unittest.main()  # pragma: no cover
