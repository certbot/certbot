# moving tests out of cli_test.py
# stopped at 822, test handle exception.
from ipdb import set_trace
import argparse
import functools
import unittest
import os
import tempfile

import six
import mock
from six.moves import reload_module  # pylint: disable=import-error

from certbot import cli
from certbot import constants
from certbot import errors
from certbot import util
from certbot.plugins import disco


class TestWhat(unittest.TestCase):
    def test_read_file(self):
        tmp_dir = tempfile.mkdtemp()
        rel_test_path = os.path.relpath(os.path.join(tmp_dir, 'foo'))
        self.assertRaises(
            argparse.ArgumentTypeError, cli.read_file, rel_test_path)

        test_contents = b'bar\n'
        with open(rel_test_path, 'wb') as f:
            f.write(test_contents)

        path, contents = cli.read_file(rel_test_path)
        self.assertEqual(path, os.path.abspath(path))
        self.assertEqual(contents, test_contents)


class TestUtil(unittest.TestCase):
    '''Why was this in there? lolz'''
    def test_punycode_ok(self):
        # Punycode is now legal, so no longer an error; instead check
        # that it's _not_ an error (at the initial sanity check stage)
        util.enforce_domain_sanity('this.is.xn--ls8h.tld')


class ParseTest(unittest.TestCase):
    '''Test the cli args entrypoint'''

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.config_dir = os.path.join(self.tmp_dir, 'config')
        self.work_dir = os.path.join(self.tmp_dir, 'work')
        self.logs_dir = os.path.join(self.tmp_dir, 'logs')
        os.mkdir(self.logs_dir)
        self.standard_args = ['--config-dir', self.config_dir,
                              '--work-dir', self.work_dir,
                              '--logs-dir', self.logs_dir, '--text']

    @classmethod
    def setUpClass(cls):
        cls.plugins = disco.PluginsRegistry.find_all()
        cls.parse = functools.partial(cli.prepare_and_parse_args, cls.plugins)

    def _help_output(self, args):
        "Run a command, and return the ouput string for scrutiny"

        output = six.StringIO()
        with mock.patch('certbot.main.sys.stdout', new=output):
            with mock.patch('certbot.main.sys.stderr'):
                self.assertRaises(SystemExit, self.parse, args, output)
        return output.getvalue()

    def test_help(self):
        self._help_output(['--help'])  # assert SystemExit is raised here
        out = self._help_output(['--help', 'all'])
        self.assertTrue("--configurator" in out)
        self.assertTrue("how a cert is deployed" in out)
        self.assertTrue("--manual-test-mode" in out)
        self.assertTrue("--text" not in out)
        self.assertTrue("--dialog" not in out)

        out = self._help_output(['-h', 'nginx'])
        if "nginx" in self.plugins:
            # may be false while building distributions without plugins
            self.assertTrue("--nginx-ctl" in out)
        self.assertTrue("--manual-test-mode" not in out)
        self.assertTrue("--checkpoints" not in out)

        out = self._help_output(['-h'])
        self.assertTrue("letsencrypt-auto" not in out)  # test cli.cli_command
        if "nginx" in self.plugins:
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
        self.assertTrue(cli.usage_strings(self.plugins)[0] in out)

    def test_parse_domains(self):
        short_args = ['-d', 'example.com']
        namespace = self.parse(short_args)
        self.assertEqual(namespace.domains, ['example.com'])

        short_args = ['-d', 'trailing.period.com.']
        namespace = self.parse(short_args)
        self.assertEqual(namespace.domains, ['trailing.period.com'])

        short_args = ['-d', 'example.com,another.net,third.org,example.com']
        namespace = self.parse(short_args)
        self.assertEqual(namespace.domains, ['example.com', 'another.net',
                                             'third.org'])

        long_args = ['--domains', 'example.com']
        namespace = self.parse(long_args)
        self.assertEqual(namespace.domains, ['example.com'])

        long_args = ['--domains', 'trailing.period.com.']
        namespace = self.parse(long_args)
        self.assertEqual(namespace.domains, ['trailing.period.com'])

        long_args = ['--domains', 'example.com,another.net,example.com']
        namespace = self.parse(long_args)
        self.assertEqual(namespace.domains, ['example.com', 'another.net'])

    def test_preferred_challenges(self):
        from acme.challenges import HTTP01, TLSSNI01, DNS01

        short_args = ['--preferred-challenges', 'http, tls-sni-01, dns']
        namespace = self.parse(short_args)

        self.assertEqual(namespace.pref_challs, [HTTP01, TLSSNI01, DNS01])

        short_args = ['--preferred-challenges', 'jumping-over-the-moon']
        self.assertRaises(argparse.ArgumentTypeError, self.parse, short_args)

    def test_server_flag(self):
        namespace = self.parse('--server example.com'.split())
        self.assertEqual(namespace.server, 'example.com')

    def test_must_staple_flag(self):
        short_args = ['--must-staple']
        namespace = self.parse(short_args)
        self.assertTrue(namespace.must_staple)
        self.assertTrue(namespace.staple)

    def _check_server_conflict_message(self, parser_args, conflicting_args):
        try:
            self.parse(parser_args)
            self.fail(  # pragma: no cover
                "The following flags didn't conflict with "
                '--server: {0}'.format(', '.join(conflicting_args)))
        except errors.Error as error:
            self.assertTrue('--server' in str(error))
            for arg in conflicting_args:
                self.assertTrue(arg in str(error))

    def test_staging_flag(self):
        short_args = ['--staging']
        namespace = self.parse(short_args)
        self.assertTrue(namespace.staging)
        self.assertEqual(namespace.server, constants.STAGING_URI)

        short_args += '--server example.com'.split()
        self._check_server_conflict_message(short_args, '--staging')

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
        config_dir = tempfile.mkdtemp()
        short_args = '--dry-run --config-dir {0}'.format(config_dir).split()
        self.assertRaises(errors.Error, self.parse, short_args)

        self._assert_dry_run_flag_worked(
            self.parse(short_args + ['auth']), False)
        self._assert_dry_run_flag_worked(
            self.parse(short_args + ['certonly']), False)
        self._assert_dry_run_flag_worked(
            self.parse(short_args + ['renew']), False)

        account_dir = os.path.join(config_dir, constants.ACCOUNTS_DIR)
        os.mkdir(account_dir)
        os.mkdir(os.path.join(account_dir, 'fake_account_dir'))

        self._assert_dry_run_flag_worked(self.parse(short_args + ['auth']), True)
        self._assert_dry_run_flag_worked(self.parse(short_args + ['renew']), True)
        short_args += ['certonly']
        self._assert_dry_run_flag_worked(self.parse(short_args), True)

        short_args += '--server example.com'.split()
        conflicts = ['--dry-run']
        self._check_server_conflict_message(short_args, '--dry-run')

        short_args += ['--staging']
        conflicts += ['--staging']
        self._check_server_conflict_message(short_args, conflicts)


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
