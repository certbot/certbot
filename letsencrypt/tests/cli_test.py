"""Tests for letsencrypt.cli."""
import argparse
import itertools
import os
import shutil
import StringIO
import traceback
import tempfile
import unittest

import mock

from acme import jose

from letsencrypt import account
from letsencrypt import cli
from letsencrypt import configuration
from letsencrypt import constants
from letsencrypt import crypto_util
from letsencrypt import errors
from letsencrypt import le_util

from letsencrypt.plugins import disco
from letsencrypt.plugins import manual

from letsencrypt.tests import renewer_test
from letsencrypt.tests import test_util


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

    def _call(self, args):
        "Run the cli with output streams and actual client mocked out"
        with mock.patch('letsencrypt.cli._suggest_donate'):
            with mock.patch('letsencrypt.cli.client') as client:
                ret, stdout, stderr = self._call_no_clientmock(args)
                return ret, stdout, stderr, client

    def _call_no_clientmock(self, args):
        "Run the client with output streams mocked out"
        args = self.standard_args + args
        with mock.patch('letsencrypt.cli._suggest_donate'):
            with mock.patch('letsencrypt.cli.sys.stdout') as stdout:
                with mock.patch('letsencrypt.cli.sys.stderr') as stderr:
                    ret = cli.main(args[:])  # NOTE: parser can alter its args!
        return ret, stdout, stderr

    def _call_stdout(self, args):
        """
        Variant of _call that preserves stdout so that it can be mocked by the
        caller.
        """
        args = self.standard_args + args
        with mock.patch('letsencrypt.cli._suggest_donate'):
            with mock.patch('letsencrypt.cli.sys.stderr') as stderr:
                with mock.patch('letsencrypt.cli.client') as client:
                    ret = cli.main(args[:])  # NOTE: parser can alter its args!
        return ret, None, stderr, client

    def test_no_flags(self):
        with MockedVerb("run") as mock_run:
            self._call([])
            self.assertEqual(1, mock_run.call_count)

    def _help_output(self, args):
        "Run a command, and return the ouput string for scrutiny"
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
        self.assertTrue("letsencrypt-auto" not in out) # test cli.cli_command
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
        self.assertTrue(cli.usage_strings(plugins)[0] in out)


    def _cli_missing_flag(self, args, message):
        "Ensure that a particular error raises a missing cli flag error containing message"
        exc = None
        try:
            with mock.patch('letsencrypt.cli.sys.stderr'):
                cli.main(self.standard_args + args[:])  # NOTE: parser can alter its args!
        except errors.MissingCommandlineFlag, exc:
            self.assertTrue(message in str(exc))
        self.assertTrue(exc is not None)

    def test_noninteractive(self):
        args = ['-n', 'certonly']
        self._cli_missing_flag(args, "specify a plugin")
        args.extend(['--standalone', '-d', 'eg.is'])
        self._cli_missing_flag(args, "register before running")
        with mock.patch('letsencrypt.cli._auth_from_domains'):
            with mock.patch('letsencrypt.cli.client.acme_from_config_key'):
                args.extend(['--email', 'io@io.is'])
                self._cli_missing_flag(args, "--agree-tos")

    @mock.patch('letsencrypt.cli.client.acme_client.Client')
    @mock.patch('letsencrypt.cli._determine_account')
    @mock.patch('letsencrypt.cli.client.Client.obtain_and_enroll_certificate')
    @mock.patch('letsencrypt.cli._auth_from_domains')
    def test_user_agent(self, afd, _obt, det, _client):
        # Normally the client is totally mocked out, but here we need more
        # arguments to automate it...
        args = ["--standalone", "certonly", "-m", "none@none.com",
                "-d", "example.com", '--agree-tos'] + self.standard_args
        det.return_value = mock.MagicMock(), None
        afd.return_value = mock.MagicMock(), "newcert"

        with mock.patch('letsencrypt.cli.client.acme_client.ClientNetwork') as acme_net:
            self._call_no_clientmock(args)
            os_ver = " ".join(le_util.get_os_info())
            ua = acme_net.call_args[1]["user_agent"]
            self.assertTrue(os_ver in ua)
            import platform
            plat = platform.platform()
            if "linux" in plat.lower():
                self.assertTrue(platform.linux_distribution()[0] in ua)

        with mock.patch('letsencrypt.cli.client.acme_client.ClientNetwork') as acme_net:
            ua = "bandersnatch"
            args += ["--user-agent", ua]
            self._call_no_clientmock(args)
            acme_net.assert_called_once_with(mock.ANY, verify_ssl=True, user_agent=ua)

    def test_install_abspath(self):
        cert = 'cert'
        key = 'key'
        chain = 'chain'
        fullchain = 'fullchain'

        with MockedVerb('install') as mock_install:
            self._call(['install', '--cert-path', cert, '--key-path', 'key',
                        '--chain-path', 'chain',
                        '--fullchain-path', 'fullchain'])

        args = mock_install.call_args[0][0]
        self.assertEqual(args.cert_path, os.path.abspath(cert))
        self.assertEqual(args.key_path, os.path.abspath(key))
        self.assertEqual(args.chain_path, os.path.abspath(chain))
        self.assertEqual(args.fullchain_path, os.path.abspath(fullchain))

    @mock.patch('letsencrypt.cli.record_chosen_plugins')
    @mock.patch('letsencrypt.cli.display_ops')
    def test_installer_selection(self, mock_display_ops, _rec):
        self._call(['install', '--domains', 'foo.bar', '--cert-path', 'cert',
                    '--key-path', 'key', '--chain-path', 'chain'])
        self.assertEqual(mock_display_ops.pick_installer.call_count, 1)

    @mock.patch('letsencrypt.le_util.exe_exists')
    def test_configurator_selection(self, mock_exe_exists):
        mock_exe_exists.return_value = True
        real_plugins = disco.PluginsRegistry.find_all()
        args = ['--apache', '--authenticator', 'standalone']

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
            self.assertTrue("MisconfigurationError" in ret)

        args = ["certonly", "--webroot"]
        ret, _, _, _ = self._call(args)
        self.assertTrue("--webroot-path must be set" in ret)

        self._cli_missing_flag(["--standalone"], "With the standalone plugin, you probably")

        with mock.patch("letsencrypt.cli._init_le_client") as mock_init:
            with mock.patch("letsencrypt.cli._auth_from_domains"):
                self._call(["certonly", "--manual", "-d", "foo.bar"])
                auth = mock_init.call_args[0][2]
                self.assertTrue(isinstance(auth, manual.Authenticator))

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

    @mock.patch('letsencrypt.cli.plugins_disco')
    @mock.patch('letsencrypt.cli.HelpfulArgumentParser.determine_help_topics')
    def test_plugins_no_args(self, _det, mock_disco):
        ifaces = []
        plugins = mock_disco.PluginsRegistry.find_all()

        _, stdout, _, _ = self._call(['plugins'])
        plugins.visible.assert_called_once_with()
        plugins.visible().ifaces.assert_called_once_with(ifaces)
        filtered = plugins.visible().ifaces()
        stdout.write.called_once_with(str(filtered))

    @mock.patch('letsencrypt.cli.plugins_disco')
    @mock.patch('letsencrypt.cli.HelpfulArgumentParser.determine_help_topics')
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
        stdout.write.called_once_with(str(verified))

    @mock.patch('letsencrypt.cli.plugins_disco')
    @mock.patch('letsencrypt.cli.HelpfulArgumentParser.determine_help_topics')
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
        stdout.write.called_once_with(str(available))

    def test_certonly_abspath(self):
        cert = 'cert'
        key = 'key'
        chain = 'chain'
        fullchain = 'fullchain'

        with MockedVerb('certonly') as mock_obtaincert:
            self._call(['certonly', '--cert-path', cert, '--key-path', 'key',
                        '--chain-path', 'chain',
                        '--fullchain-path', 'fullchain'])

        args = mock_obtaincert.call_args[0][0]
        self.assertEqual(args.cert_path, os.path.abspath(cert))
        self.assertEqual(args.key_path, os.path.abspath(key))
        self.assertEqual(args.chain_path, os.path.abspath(chain))
        self.assertEqual(args.fullchain_path, os.path.abspath(fullchain))

    def test_certonly_bad_args(self):
        ret, _, _, _ = self._call(['-d', 'foo.bar', 'certonly', '--csr', CSR])
        self.assertEqual(ret, '--domains and --csr are mutually exclusive')

        ret, _, _, _ = self._call(['-a', 'bad_auth', 'certonly'])
        self.assertEqual(ret, 'The requested bad_auth plugin does not appear to be installed')

    def test_check_config_sanity_domain(self):
        # Punycode
        self.assertRaises(errors.ConfigurationError,
                          self._call,
                          ['-d', 'this.is.xn--ls8h.tld'])
        # FQDN
        self.assertRaises(errors.ConfigurationError,
                          self._call,
                          ['-d', 'comma,gotwrong.tld'])
        # FQDN 2
        self.assertRaises(errors.ConfigurationError,
                          self._call,
                          ['-d', 'illegal.character=.tld'])
        # Wildcard
        self.assertRaises(errors.ConfigurationError,
                          self._call,
                          ['-d', '*.wildcard.tld'])

    def test_parse_domains(self):
        plugins = disco.PluginsRegistry.find_all()

        short_args = ['-d', 'example.com']
        namespace = cli.prepare_and_parse_args(plugins, short_args)
        self.assertEqual(namespace.domains, ['example.com'])

        short_args = ['-d', 'example.com,another.net,third.org,example.com']
        namespace = cli.prepare_and_parse_args(plugins, short_args)
        self.assertEqual(namespace.domains, ['example.com', 'another.net',
                                             'third.org'])

        long_args = ['--domains', 'example.com']
        namespace = cli.prepare_and_parse_args(plugins, long_args)
        self.assertEqual(namespace.domains, ['example.com'])

        long_args = ['--domains', 'example.com,another.net,example.com']
        namespace = cli.prepare_and_parse_args(plugins, long_args)
        self.assertEqual(namespace.domains, ['example.com', 'another.net'])

    def test_parse_server(self):
        plugins = disco.PluginsRegistry.find_all()
        short_args = ['--server', 'example.com']
        namespace = cli.prepare_and_parse_args(plugins, short_args)
        self.assertEqual(namespace.server, 'example.com')

        short_args = ['--staging']
        namespace = cli.prepare_and_parse_args(plugins, short_args)
        self.assertEqual(namespace.server, constants.STAGING_URI)

        short_args = ['--staging', '--server', 'example.com']
        self.assertRaises(errors.Error, cli.prepare_and_parse_args, plugins, short_args)

    def test_parse_webroot(self):
        plugins = disco.PluginsRegistry.find_all()
        webroot_args = ['--webroot', '-w', '/var/www/example',
            '-d', 'example.com,www.example.com', '-w', '/var/www/superfluous',
            '-d', 'superfluo.us', '-d', 'www.superfluo.us']
        namespace = cli.prepare_and_parse_args(plugins, webroot_args)
        self.assertEqual(namespace.webroot_map, {
            'example.com': '/var/www/example',
            'www.example.com': '/var/www/example',
            'www.superfluo.us': '/var/www/superfluous',
            'superfluo.us': '/var/www/superfluous'})

        webroot_args = ['-d', 'stray.example.com'] + webroot_args
        self.assertRaises(errors.Error, cli.prepare_and_parse_args, plugins, webroot_args)

        webroot_map_args = ['--webroot-map', '{"eg.com" : "/tmp"}']
        namespace = cli.prepare_and_parse_args(plugins, webroot_map_args)
        self.assertEqual(namespace.webroot_map, {u"eg.com": u"/tmp"})

    @mock.patch('letsencrypt.cli._suggest_donate')
    @mock.patch('letsencrypt.crypto_util.notAfter')
    @mock.patch('letsencrypt.cli.zope.component.getUtility')
    def test_certonly_new_request_success(self, mock_get_utility, mock_notAfter, _suggest):
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
            mock_renewal.return_value = ("newcert", None)
            with mock.patch('letsencrypt.cli._init_le_client') as mock_init:
                mock_init.return_value = mock_client
                self._call(['-d', 'foo.bar', '-a', 'standalone', 'certonly'])

    @mock.patch('letsencrypt.cli._suggest_donate')
    @mock.patch('letsencrypt.cli.zope.component.getUtility')
    @mock.patch('letsencrypt.cli._treat_as_renewal')
    @mock.patch('letsencrypt.cli._init_le_client')
    def test_certonly_renewal(self, mock_init, mock_renewal, mock_get_utility, _suggest):
        cert_path = 'letsencrypt/tests/testdata/cert.pem'
        chain_path = '/etc/letsencrypt/live/foo.bar/fullchain.pem'

        mock_lineage = mock.MagicMock(cert=cert_path, fullchain=chain_path)
        mock_certr = mock.MagicMock()
        mock_key = mock.MagicMock(pem='pem_key')
        mock_renewal.return_value = ("renew", mock_lineage)
        mock_client = mock.MagicMock()
        mock_client.obtain_certificate.return_value = (mock_certr, 'chain',
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

    @mock.patch('letsencrypt.cli._suggest_donate')
    @mock.patch('letsencrypt.crypto_util.notAfter')
    @mock.patch('letsencrypt.cli.display_ops.pick_installer')
    @mock.patch('letsencrypt.cli.zope.component.getUtility')
    @mock.patch('letsencrypt.cli._init_le_client')
    @mock.patch('letsencrypt.cli.record_chosen_plugins')
    def test_certonly_csr(self, _rec, mock_init, mock_get_utility,
                          mock_pick_installer, mock_notAfter, _suggest):
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

    @mock.patch('letsencrypt.cli.client.acme_client')
    def test_revoke_with_key(self, mock_acme_client):
        server = 'foo.bar'
        self._call_no_clientmock(['--cert-path', CERT, '--key-path', KEY,
                                 '--server', server, 'revoke'])
        with open(KEY) as f:
            mock_acme_client.Client.assert_called_once_with(
                server, key=jose.JWK.load(f.read()), net=mock.ANY)
        with open(CERT) as f:
            cert = crypto_util.pyopenssl_load_certificate(f.read())[0]
            mock_revoke = mock_acme_client.Client().revoke
            mock_revoke.assert_called_once_with(jose.ComparableX509(cert))

    @mock.patch('letsencrypt.cli._determine_account')
    def test_revoke_without_key(self, mock_determine_account):
        mock_determine_account.return_value = (mock.MagicMock(), None)
        _, _, _, client = self._call(['--cert-path', CERT, 'revoke'])
        with open(CERT) as f:
            cert = crypto_util.pyopenssl_load_certificate(f.read())[0]
            mock_revoke = client.acme_from_config_key().revoke
            mock_revoke.assert_called_once_with(jose.ComparableX509(cert))

    @mock.patch('letsencrypt.cli.sys')
    def test_handle_exception(self, mock_sys):
        # pylint: disable=protected-access
        from acme import messages

        args = mock.MagicMock()
        mock_open = mock.mock_open()

        with mock.patch('letsencrypt.cli.open', mock_open, create=True):
            exception = Exception('detail')
            args.verbose_count = 1
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

        exception = messages.Error(detail='alpha', typ='urn:acme:error:triffid',
                                   title='beta')
        args = mock.MagicMock(debug=False, verbose_count=-3)
        cli._handle_exception(
            messages.Error, exc_value=exception, trace=None, args=args)
        error_msg = mock_sys.exit.call_args_list[-1][0][0]
        self.assertTrue('unexpected error' in error_msg)
        self.assertTrue('acme:error' not in error_msg)
        self.assertTrue('alpha' in error_msg)
        self.assertTrue('beta' in error_msg)
        args = mock.MagicMock(debug=False, verbose_count=1)
        cli._handle_exception(
            messages.Error, exc_value=exception, trace=None, args=args)
        error_msg = mock_sys.exit.call_args_list[-1][0][0]
        self.assertTrue('unexpected error' in error_msg)
        self.assertTrue('acme:error' in error_msg)
        self.assertTrue('alpha' in error_msg)

        interrupt = KeyboardInterrupt('detail')
        cli._handle_exception(
            KeyboardInterrupt, exc_value=interrupt, trace=None, args=None)
        mock_sys.exit.assert_called_with(''.join(
            traceback.format_exception_only(KeyboardInterrupt, interrupt)))

    def test_read_file(self):
        rel_test_path = os.path.relpath(os.path.join(self.tmp_dir, 'foo'))
        self.assertRaises(
            argparse.ArgumentTypeError, cli.read_file, rel_test_path)

        test_contents = 'bar\n'
        with open(rel_test_path, 'w') as f:
            f.write(test_contents)

        path, contents = cli.read_file(rel_test_path)
        self.assertEqual(path, os.path.abspath(path))
        self.assertEqual(contents, test_contents)

    def test_agree_dev_preview_config(self):
        with MockedVerb('run') as mocked_run:
            self._call(['-c', test_util.vector_path('cli.ini')])
        self.assertTrue(mocked_run.called)


class DetermineAccountTest(unittest.TestCase):
    """Tests for letsencrypt.cli._determine_account."""

    def setUp(self):
        self.args = mock.MagicMock(account=None, email=None,
            register_unsafely_without_email=False)
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
