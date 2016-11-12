# moving tests out of cli_test.py
# stopped at 822, test handle exception.
from ipdb import set_trace
import argparse
import functools
import unittest
import os
import tempfile

from certbot import cli
from certbot import constants
from certbot import errors
from certbot import util
from certbot.plugins import disco


class TestUtil(unittest.TestCase):
    '''Why was this in there? lolz'''
    def test_punycode_ok(self):
        # Punycode is now legal, so no longer an error; instead check
        # that it's _not_ an error (at the initial sanity check stage)
        util.enforce_domain_sanity('this.is.xn--ls8h.tld')


class ParseTest(unittest.TestCase):
    '''Test the cli args entrypoint'''

    @classmethod
    def setUpClass(cls):
        cls.plugins = disco.PluginsRegistry.find_all()
        cls.parse = functools.partial(cli.prepare_and_parse_args, cls.plugins)

    def test_help(self):
        self.assertRaises(SystemExit, self.parse, ['--help'])
        self.assertRaises(SystemExit, self.parse, ['--help', 'all'])

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
