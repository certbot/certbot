"""Tests for letsencrypt.cli."""
import argparse
import functools
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
from letsencrypt import storage

from letsencrypt.plugins import disco
from letsencrypt.plugins import manual

from letsencrypt.tests import storage_test
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
        with mock.patch('letsencrypt.cli.client') as client:
            ret, stdout, stderr = self._call_no_clientmock(args)
            return ret, stdout, stderr, client

    def _call_no_clientmock(self, args):
        "Run the client with output streams mocked out"
        args = self.standard_args + args
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
        except errors.MissingCommandlineFlag as exc:
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
        try:
            self._call(args)
            assert False, "Exception should have been raised"
        except errors.PluginSelectionError as e:
            self.assertTrue("please set either --webroot-path" in e.message)

        self._cli_missing_flag(["--standalone"], "With the standalone plugin, you probably")

        with mock.patch("letsencrypt.cli._init_le_client") as mock_init:
            with mock.patch("letsencrypt.cli._auth_from_domains") as mock_afd:
                mock_afd.return_value = (mock.MagicMock(), mock.MagicMock())
                self._call(["certonly", "--manual", "-d", "foo.bar"])
                unused_config, auth, unused_installer = mock_init.call_args[0]
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
            self.assertTrue('The requested bad_auth plugin does not appear' in e.message)

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

        # Bare IP address (this is actually a different error message now)
        self.assertRaises(errors.ConfigurationError,
                          self._call,
                          ['-d', '204.11.231.35'])

    def test_run_with_csr(self):
        # This is an error because you can only use --csr with certonly
        try:
            self._call(['--csr', CSR])
        except errors.Error as e:
            assert "Please try the certonly" in e.message
            return
        assert False, "Expected supplying --csr to fail with default verb"

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
            self.assertTrue('--server' in error.message)
            for arg in conflicting_args:
                self.assertTrue(arg in error.message)

    def test_staging_flag(self):
        parse = self._get_argument_parser()
        short_args = ['--staging']
        namespace = parse(short_args)
        self.assertTrue(namespace.staging)
        self.assertEqual(namespace.server, constants.STAGING_URI)

        short_args += '--server example.com'.split()
        self._check_server_conflict_message(short_args, '--staging')

    def _assert_dry_run_flag_worked(self, namespace):
        self.assertTrue(namespace.dry_run)
        self.assertTrue(namespace.break_my_certs)
        self.assertTrue(namespace.staging)
        self.assertEqual(namespace.server, constants.STAGING_URI)

    def test_dry_run_flag(self):
        parse = self._get_argument_parser()
        short_args = ['--dry-run']
        self.assertRaises(errors.Error, parse, short_args)

        self._assert_dry_run_flag_worked(parse(short_args + ['auth']))
        short_args += ['certonly']
        self._assert_dry_run_flag_worked(parse(short_args))

        short_args += '--server example.com'.split()
        conflicts = ['--dry-run']
        self._check_server_conflict_message(short_args, '--dry-run')

        short_args += ['--staging']
        conflicts += ['--staging']
        self._check_server_conflict_message(short_args, conflicts)

    def _webroot_map_test(self, map_arg, path_arg, domains_arg, # pylint: disable=too-many-arguments
                          expected_map, expectect_domains, extra_args=None):
        parse = self._get_argument_parser()
        webroot_map_args = extra_args if extra_args else []
        if map_arg:
            webroot_map_args.extend(["--webroot-map", map_arg])
        if path_arg:
            webroot_map_args.extend(["-w", path_arg])
        if domains_arg:
            webroot_map_args.extend(["-d", domains_arg])
        namespace = parse(webroot_map_args)
        domains = cli._find_domains(namespace, mock.MagicMock()) # pylint: disable=protected-access
        self.assertEqual(namespace.webroot_map, expected_map)
        self.assertEqual(set(domains), set(expectect_domains))

    def test_parse_webroot(self):
        parse = self._get_argument_parser()
        webroot_args = ['--webroot', '-w', '/var/www/example',
            '-d', 'example.com,www.example.com', '-w', '/var/www/superfluous',
            '-d', 'superfluo.us', '-d', 'www.superfluo.us']
        namespace = parse(webroot_args)
        self.assertEqual(namespace.webroot_map, {
            'example.com': '/var/www/example',
            'www.example.com': '/var/www/example',
            'www.superfluo.us': '/var/www/superfluous',
            'superfluo.us': '/var/www/superfluous'})

        webroot_args = ['-d', 'stray.example.com'] + webroot_args
        self.assertRaises(errors.Error, parse, webroot_args)

        simple_map = '{"eg.com" : "/tmp"}'
        expected_map = {"eg.com": "/tmp"}
        self._webroot_map_test(simple_map, None, None, expected_map, ["eg.com"])

        # test merging webroot maps from the cli and a webroot map
        expected_map["eg2.com"] = "/tmp2"
        domains = ["eg.com", "eg2.com"]
        self._webroot_map_test(simple_map, "/tmp2", "eg2.com,eg.com", expected_map, domains)

        # test inclusion of interactively specified domains in the webroot map
        with mock.patch('letsencrypt.cli.display_ops.choose_names') as mock_choose:
            mock_choose.return_value = domains
            expected_map["eg2.com"] = "/tmp"
            self._webroot_map_test(None, "/tmp", None, expected_map, domains)

        extra_args = ['-c', test_util.vector_path('webrootconftest.ini')]
        self._webroot_map_test(None, None, None, expected_map, domains, extra_args)

        webroot_map_args = ['--webroot-map',
                            '{"eg.com.,www.eg.com": "/tmp", "eg.is.": "/tmp2"}']
        namespace = parse(webroot_map_args)
        self.assertEqual(namespace.webroot_map,
                         {"eg.com": "/tmp", "www.eg.com": "/tmp", "eg.is": "/tmp2"})

    def _certonly_new_request_common(self, mock_client, args=None):
        with mock.patch('letsencrypt.cli._treat_as_renewal') as mock_renewal:
            mock_renewal.return_value = ("newcert", None)
            with mock.patch('letsencrypt.cli._init_le_client') as mock_init:
                mock_init.return_value = mock_client
                if args is None:
                    args = []
                args += '-d foo.bar -a standalone certonly'.split()
                self._call(args)

    @mock.patch('letsencrypt.cli.zope.component.getUtility')
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
                             args=None, renew=True, error_expected=False):
        # pylint: disable=too-many-locals,too-many-arguments
        cert_path = 'letsencrypt/tests/testdata/cert.pem'
        chain_path = '/etc/letsencrypt/live/foo.bar/fullchain.pem'
        mock_lineage = mock.MagicMock(cert=cert_path, fullchain=chain_path)
        mock_lineage.should_autorenew.return_value = due_for_renewal
        mock_certr = mock.MagicMock()
        mock_key = mock.MagicMock(pem='pem_key')
        mock_client = mock.MagicMock()
        mock_client.obtain_certificate.return_value = (mock_certr, 'chain',
                                                       mock_key, 'csr')
        try:
            with mock.patch('letsencrypt.cli._find_duplicative_certs') as mock_fdc:
                mock_fdc.return_value = (mock_lineage, None)
                with mock.patch('letsencrypt.cli._init_le_client') as mock_init:
                    mock_init.return_value = mock_client
                    get_utility_path = 'letsencrypt.cli.zope.component.getUtility'
                    with mock.patch(get_utility_path) as mock_get_utility:
                        with mock.patch('letsencrypt.cli.OpenSSL') as mock_ssl:
                            mock_latest = mock.MagicMock()
                            mock_latest.get_issuer.return_value = "Fake fake"
                            mock_ssl.crypto.load_certificate.return_value = mock_latest
                            with mock.patch('letsencrypt.cli.crypto_util'):
                                if not args:
                                    args = ['-d', 'isnot.org', '-a', 'standalone', 'certonly']
                                if extra_args:
                                    args += extra_args
                                try:
                                    ret, _, _, _ = self._call(args)
                                    if ret:
                                        print "Returned", ret
                                        raise AssertionError(ret)
                                    assert not error_expected, "renewal should have errored"
                                except: # pylint: disable=bare-except
                                    if not error_expected:
                                        raise AssertionError(
                                            "Unexpected renewal error:\n" +
                                            traceback.format_exc())

            if renew:
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

        return mock_lineage, mock_get_utility

    def test_certonly_renewal(self):
        lineage, get_utility = self._test_renewal_common(True, [])
        self.assertEqual(lineage.save_successor.call_count, 1)
        lineage.update_all_links_to.assert_called_once_with(
            lineage.latest_common_version())
        cert_msg = get_utility().add_message.call_args_list[0][0][0]
        self.assertTrue('fullchain.pem' in cert_msg)
        self.assertTrue('donate' in get_utility().add_message.call_args[0][0])

    def test_certonly_renewal_triggers(self):
        # --dry-run should force renewal
        _, get_utility = self._test_renewal_common(False, ['--dry-run', '--keep'],
                                                   log_out="simulating renewal")
        self.assertEqual(get_utility().add_message.call_count, 1)
        self.assertTrue('dry run' in get_utility().add_message.call_args[0][0])

        _, _ = self._test_renewal_common(False, ['--renew-by-default', '-tvv', '--debug'],
                                        log_out="Auto-renewal forced")
        self.assertEqual(get_utility().add_message.call_count, 1)

        _, _ = self._test_renewal_common(False, ['-tvv', '--debug', '--keep'],
                                        log_out="not yet due", renew=False)

    def _dump_log(self):
        with open(os.path.join(self.logs_dir, "letsencrypt.log")) as lf:
            print "Logs:"
            print lf.read()


    def _make_test_renewal_conf(self, testfile):
        with open(test_util.vector_path(testfile)) as src:
            # put the correct path for cert.pem, chain.pem etc in the renewal conf
            renewal_conf = src.read().replace("MAGICDIR", test_util.vector_path())
        rd = os.path.join(self.config_dir, "renewal")
        if not os.path.exists(rd):
            os.makedirs(rd)
        rc = os.path.join(rd, "sample-renewal.conf")
        with open(rc, "w") as dest:
            dest.write(renewal_conf)
        return rc

    def test_renew_verb(self):
        self._make_test_renewal_conf('sample-renewal.conf')
        args = ["renew", "--dry-run", "-tvv"]
        self._test_renewal_common(True, [], args=args, renew=True)

    @mock.patch("letsencrypt.cli._set_by_cli")
    def test_ancient_webroot_renewal_conf(self, mock_set_by_cli):
        mock_set_by_cli.return_value = False
        rc_path = self._make_test_renewal_conf('sample-renewal-ancient.conf')
        args = mock.MagicMock(account=None, email=None, webroot_path=None)
        config = configuration.NamespaceConfig(args)
        lineage = storage.RenewableCert(rc_path,
            configuration.RenewerConfiguration(config))
        renewalparams = lineage.configuration["renewalparams"]
        # pylint: disable=protected-access
        cli._restore_webroot_config(config, renewalparams)
        self.assertEqual(config.webroot_path, ["/var/www/"])

    def test_renew_verb_empty_config(self):
        rd = os.path.join(self.config_dir, 'renewal')
        if not os.path.exists(rd):
            os.makedirs(rd)
        with open(os.path.join(rd, 'empty.conf'), 'w'):
            pass  # leave the file empty
        args = ["renew", "--dry-run", "-tvv"]
        self._test_renewal_common(False, [], args=args, renew=False, error_expected=True)

    def _make_dummy_renewal_config(self):
        renewer_configs_dir = os.path.join(self.config_dir, 'renewal')
        os.makedirs(renewer_configs_dir)
        with open(os.path.join(renewer_configs_dir, 'test.conf'), 'w') as f:
            f.write("My contents don't matter")

    def _test_renew_common(self, renewalparams=None, error_expected=False,
                           names=None, assert_oc_called=None):
        self._make_dummy_renewal_config()
        with mock.patch('letsencrypt.storage.RenewableCert') as mock_rc:
            mock_lineage = mock.MagicMock()
            mock_lineage.fullchain = "somepath/fullchain.pem"
            if renewalparams is not None:
                mock_lineage.configuration = {'renewalparams': renewalparams}
            if names is not None:
                mock_lineage.names.return_value = names
            mock_rc.return_value = mock_lineage
            with mock.patch('letsencrypt.cli.obtain_cert') as mock_obtain_cert:
                self._test_renewal_common(True, None, error_expected=error_expected,
                                          args=['renew'], renew=False)
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

    def test_renew_with_bad_domain(self):
        renewalparams = {'authenticator': 'webroot'}
        names = ['*.example.com']
        self._test_renew_common(renewalparams=renewalparams, error_expected=True,
                                names=names, assert_oc_called=False)

    def test_renew_plugin_config_restoration(self):
        renewalparams = {'authenticator': 'webroot',
                         'webroot_path': 'None',
                         'webroot_imaginary_flag': '42'}
        self._test_renew_common(renewalparams=renewalparams,
                                assert_oc_called=True)

    def test_renew_reconstitute_error(self):
        # pylint: disable=protected-access
        with mock.patch('letsencrypt.cli._reconstitute') as mock_reconstitute:
            mock_reconstitute.side_effect = Exception
            self._test_renew_common(assert_oc_called=False, error_expected=True)

    def test_renew_obtain_cert_error(self):
        self._make_dummy_renewal_config()
        with mock.patch('letsencrypt.storage.RenewableCert') as mock_rc:
            mock_lineage = mock.MagicMock()
            mock_lineage.fullchain = "somewhere/fullchain.pem"
            mock_rc.return_value = mock_lineage
            mock_lineage.configuration = {
                'renewalparams': {'authenticator': 'webroot'}}
            with mock.patch('letsencrypt.cli.obtain_cert') as mock_obtain_cert:
                mock_obtain_cert.side_effect = Exception
                self._test_renewal_common(True, None, error_expected=True,
                                          args=['renew'], renew=False)

    def test_renew_with_bad_cli_args(self):
        self._test_renewal_common(True, None, args='renew -d example.com'.split(),
                                  renew=False, error_expected=True)
        self._test_renewal_common(True, None, args='renew --csr {0}'.format(CSR).split(),
                                  renew=False, error_expected=True)

    @mock.patch('letsencrypt.cli.zope.component.getUtility')
    @mock.patch('letsencrypt.cli._treat_as_renewal')
    @mock.patch('letsencrypt.cli._init_le_client')
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
        with mock.patch('letsencrypt.cli._init_le_client') as mock_init:
            mock_init.return_value = mock_client
            get_utility_path = 'letsencrypt.cli.zope.component.getUtility'
            with mock.patch(get_utility_path) as mock_get_utility:
                chain_path = '/etc/letsencrypt/live/example.com/chain.pem'
                full_path = '/etc/letsencrypt/live/example.com/fullchain.pem'
                args = ('-a standalone certonly --csr {0} --cert-path {1} '
                        '--chain-path {2} --fullchain-path {3}').format(
                            CSR, cert_path, chain_path, full_path).split()
                if extra_args:
                    args += extra_args
                with mock.patch('letsencrypt.cli.crypto_util'):
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

        config = mock.MagicMock()
        mock_open = mock.mock_open()

        with mock.patch('letsencrypt.cli.open', mock_open, create=True):
            exception = Exception('detail')
            config.verbose_count = 1
            cli._handle_exception(
                Exception, exc_value=exception, trace=None, config=None)
            mock_open().write.assert_called_once_with(''.join(
                traceback.format_exception_only(Exception, exception)))
            error_msg = mock_sys.exit.call_args_list[0][0][0]
            self.assertTrue('unexpected error' in error_msg)

        with mock.patch('letsencrypt.cli.open', mock_open, create=True):
            mock_open.side_effect = [KeyboardInterrupt]
            error = errors.Error('detail')
            cli._handle_exception(
                errors.Error, exc_value=error, trace=None, config=None)
            # assert_any_call used because sys.exit doesn't exit in cli.py
            mock_sys.exit.assert_any_call(''.join(
                traceback.format_exception_only(errors.Error, error)))

        exception = messages.Error(detail='alpha', typ='urn:acme:error:triffid',
                                   title='beta')
        config = mock.MagicMock(debug=False, verbose_count=-3)
        cli._handle_exception(
            messages.Error, exc_value=exception, trace=None, config=config)
        error_msg = mock_sys.exit.call_args_list[-1][0][0]
        self.assertTrue('unexpected error' in error_msg)
        self.assertTrue('acme:error' not in error_msg)
        self.assertTrue('alpha' in error_msg)
        self.assertTrue('beta' in error_msg)
        config = mock.MagicMock(debug=False, verbose_count=1)
        cli._handle_exception(
            messages.Error, exc_value=exception, trace=None, config=config)
        error_msg = mock_sys.exit.call_args_list[-1][0][0]
        self.assertTrue('unexpected error' in error_msg)
        self.assertTrue('acme:error' in error_msg)
        self.assertTrue('alpha' in error_msg)

        interrupt = KeyboardInterrupt('detail')
        cli._handle_exception(
            KeyboardInterrupt, exc_value=interrupt, trace=None, config=None)
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

    @mock.patch('letsencrypt.client.display_ops.choose_account')
    def test_multiple_accounts(self, mock_choose_accounts):
        for acc in self.accs:
            self.account_storage.save(acc)
        mock_choose_accounts.return_value = self.accs[1]
        self.assertEqual((self.accs[1], None), self._call())
        self.assertEqual(
            set(mock_choose_accounts.call_args[0][0]), set(self.accs))
        self.assertEqual(self.accs[1].id, self.config.account)
        self.assertTrue(self.config.email is None)

    @mock.patch('letsencrypt.client.display_ops.get_email')
    def test_no_accounts_no_email(self, mock_get_email):
        mock_get_email.return_value = 'foo@bar.baz'

        with mock.patch('letsencrypt.cli.client') as client:
            client.register.return_value = (
                self.accs[0], mock.sentinel.acme)
            self.assertEqual((self.accs[0], mock.sentinel.acme), self._call())
        client.register.assert_called_once_with(
            self.config, self.account_storage, tos_cb=mock.ANY)

        self.assertEqual(self.accs[0].id, self.config.account)
        self.assertEqual('foo@bar.baz', self.config.email)

    def test_no_accounts_email(self):
        self.config.email = 'other email'
        with mock.patch('letsencrypt.cli.client') as client:
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
