"""Tests for certbot._internal.cli."""
import argparse
import copy
import tempfile
import unittest

import mock
import six
from six.moves import reload_module  # pylint: disable=import-error

from acme import challenges
from certbot import errors
from certbot._internal import cli
from certbot._internal import constants
from certbot._internal.plugins import disco
from certbot.compat import filesystem
from certbot.compat import os
import certbot.tests.util as test_util
from certbot.tests.util import TempDirTestCase

PLUGINS = disco.PluginsRegistry.find_all()


class TestReadFile(TempDirTestCase):
    """Test cli.read_file"""
    def test_read_file(self):
        curr_dir = os.getcwd()
        try:
            # On Windows current directory may be on a different drive than self.tempdir.
            # However a relative path between two different drives is invalid. So we move to
            # self.tempdir to ensure that we stay on the same drive.
            os.chdir(self.tempdir)
            rel_test_path = os.path.relpath(os.path.join(self.tempdir, 'foo'))
            self.assertRaises(
                argparse.ArgumentTypeError, cli.read_file, rel_test_path)

            test_contents = b'bar\n'
            with open(rel_test_path, 'wb') as f:
                f.write(test_contents)

            path, contents = cli.read_file(rel_test_path)
            self.assertEqual(path, os.path.abspath(path))
            self.assertEqual(contents, test_contents)
        finally:
            os.chdir(curr_dir)


class FlagDefaultTest(unittest.TestCase):
    """Tests cli.flag_default"""

    def test_default_directories(self):
        if os.name != 'nt':
            self.assertEqual(cli.flag_default('config_dir'), '/etc/letsencrypt')
            self.assertEqual(cli.flag_default('work_dir'), '/var/lib/letsencrypt')
            self.assertEqual(cli.flag_default('logs_dir'), '/var/log/letsencrypt')
        else:
            self.assertEqual(cli.flag_default('config_dir'), 'C:\\Certbot')
            self.assertEqual(cli.flag_default('work_dir'), 'C:\\Certbot\\lib')
            self.assertEqual(cli.flag_default('logs_dir'), 'C:\\Certbot\\log')


class ParseTest(unittest.TestCase):
    '''Test the cli args entrypoint'''


    def setUp(self):
        reload_module(cli)

    @staticmethod
    def _unmocked_parse(*args, **kwargs):
        """Get result of cli.prepare_and_parse_args."""
        return cli.prepare_and_parse_args(PLUGINS, *args, **kwargs)

    @staticmethod
    def parse(*args, **kwargs):
        """Mocks zope.component.getUtility and calls _unmocked_parse."""
        with test_util.patch_get_utility():
            return ParseTest._unmocked_parse(*args, **kwargs)

    def _help_output(self, args):
        "Run a command, and return the output string for scrutiny"

        output = six.StringIO()

        def write_msg(message, *args, **kwargs): # pylint: disable=missing-docstring,unused-argument
            output.write(message)

        with mock.patch('certbot._internal.main.sys.stdout', new=output):
            with test_util.patch_get_utility() as mock_get_utility:
                mock_get_utility().notification.side_effect = write_msg
                with mock.patch('certbot._internal.main.sys.stderr'):
                    self.assertRaises(SystemExit, self._unmocked_parse, args, output)

        return output.getvalue()

    @mock.patch("certbot._internal.cli.flag_default")
    def test_cli_ini_domains(self, mock_flag_default):
        with tempfile.NamedTemporaryFile() as tmp_config:
            tmp_config.close()  # close now because of compatibility issues on Windows
            # use a shim to get ConfigArgParse to pick up tmp_config
            shim = (
                    lambda v: copy.deepcopy(constants.CLI_DEFAULTS[v])
                    if v != "config_files"
                    else [tmp_config.name]
                    )
            mock_flag_default.side_effect = shim

            namespace = self.parse(["certonly"])
            self.assertEqual(namespace.domains, [])
            with open(tmp_config.name, 'w') as file_h:
                file_h.write("domains = example.com")
            namespace = self.parse(["certonly"])
            self.assertEqual(namespace.domains, ["example.com"])
            namespace = self.parse(["renew"])
            self.assertEqual(namespace.domains, [])

    def test_no_args(self):
        namespace = self.parse([])
        for d in ('config_dir', 'logs_dir', 'work_dir'):
            self.assertEqual(getattr(namespace, d), cli.flag_default(d))

    def test_install_abspath(self):
        cert = 'cert'
        key = 'key'
        chain = 'chain'
        fullchain = 'fullchain'

        with mock.patch('certbot._internal.main.install'):
            namespace = self.parse(['install', '--cert-path', cert,
                                    '--key-path', 'key', '--chain-path',
                                    'chain', '--fullchain-path', 'fullchain'])

        self.assertEqual(namespace.cert_path, os.path.abspath(cert))
        self.assertEqual(namespace.key_path, os.path.abspath(key))
        self.assertEqual(namespace.chain_path, os.path.abspath(chain))
        self.assertEqual(namespace.fullchain_path, os.path.abspath(fullchain))

    def test_help(self):
        self._help_output(['--help'])  # assert SystemExit is raised here
        out = self._help_output(['--help', 'all'])
        self.assertTrue("--configurator" in out)
        self.assertTrue("how a certificate is deployed" in out)
        self.assertTrue("--webroot-path" in out)
        self.assertTrue("--text" not in out)
        self.assertTrue("--dialog" not in out)
        self.assertTrue("%s" not in out)
        self.assertTrue("{0}" not in out)
        self.assertTrue("--renew-hook" not in out)

        out = self._help_output(['-h', 'nginx'])
        if "nginx" in PLUGINS:
            # may be false while building distributions without plugins
            self.assertTrue("--nginx-ctl" in out)
        self.assertTrue("--webroot-path" not in out)
        self.assertTrue("--checkpoints" not in out)

        out = self._help_output(['-h'])
        self.assertTrue("letsencrypt-auto" not in out)  # test cli.cli_command
        if "nginx" in PLUGINS:
            self.assertTrue("Use the Nginx plugin" in out)
        else:
            self.assertTrue("(the certbot nginx plugin is not" in out)

        out = self._help_output(['--help', 'plugins'])
        self.assertTrue("--webroot-path" not in out)
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
        self.assertTrue("--reason" in out)
        self.assertTrue("--delete-after-revoke" in out)
        self.assertTrue("--no-delete-after-revoke" in out)

        out = self._help_output(['-h', 'register'])
        self.assertTrue("--cert-path" not in out)
        self.assertTrue("--key-path" not in out)

        out = self._help_output(['-h'])
        self.assertTrue(cli.SHORT_USAGE in out)
        self.assertTrue(cli.COMMAND_OVERVIEW[:100] in out)
        self.assertTrue("%s" not in out)
        self.assertTrue("{0}" not in out)

    def test_help_no_dashes(self):
        self._help_output(['help'])  # assert SystemExit is raised here

        out = self._help_output(['help', 'all'])
        self.assertTrue("--configurator" in out)
        self.assertTrue("how a certificate is deployed" in out)
        self.assertTrue("--webroot-path" in out)
        self.assertTrue("--text" not in out)
        self.assertTrue("--dialog" not in out)
        self.assertTrue("%s" not in out)
        self.assertTrue("{0}" not in out)

        out = self._help_output(['help', 'install'])
        self.assertTrue("--cert-path" in out)
        self.assertTrue("--key-path" in out)

        out = self._help_output(['help', 'revoke'])
        self.assertTrue("--cert-path" in out)
        self.assertTrue("--key-path" in out)

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
        short_args = ['--preferred-challenges', 'http, dns']
        namespace = self.parse(short_args)

        expected = [challenges.HTTP01.typ, challenges.DNS01.typ]
        self.assertEqual(namespace.pref_challs, expected)

        short_args = ['--preferred-challenges', 'jumping-over-the-moon']
        # argparse.ArgumentError makes argparse print more information
        # to stderr and call sys.exit()
        with mock.patch('sys.stderr'):
            self.assertRaises(SystemExit, self.parse, short_args)

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
        filesystem.mkdir(account_dir)
        filesystem.mkdir(os.path.join(account_dir, 'fake_account_dir'))

        self._assert_dry_run_flag_worked(self.parse(short_args + ['auth']), True)
        self._assert_dry_run_flag_worked(self.parse(short_args + ['renew']), True)
        self._assert_dry_run_flag_worked(self.parse(short_args + ['certonly']), True)

        short_args += ['certonly']

        # `--dry-run --server example.com` should emit example.com
        self.assertEqual(self.parse(short_args + ['--server', 'example.com']).server,
                         'example.com')

        # `--dry-run --server STAGING_URI` should emit STAGING_URI
        self.assertEqual(self.parse(short_args + ['--server', constants.STAGING_URI]).server,
                         constants.STAGING_URI)

        # `--dry-run --server LIVE` should emit STAGING_URI
        self.assertEqual(self.parse(short_args + ['--server', cli.flag_default("server")]).server,
                         constants.STAGING_URI)

        # `--dry-run --server example.com --staging` should emit an error
        conflicts = ['--staging']
        self._check_server_conflict_message(short_args + ['--server', 'example.com', '--staging'],
                                            conflicts)

    def test_option_was_set(self):
        key_size_option = 'rsa_key_size'
        key_size_value = cli.flag_default(key_size_option)
        self.parse('--rsa-key-size {0}'.format(key_size_value).split())

        self.assertTrue(cli.option_was_set(key_size_option, key_size_value))
        self.assertTrue(cli.option_was_set('no_verify_ssl', True))

        config_dir_option = 'config_dir'
        self.assertFalse(cli.option_was_set(
            config_dir_option, cli.flag_default(config_dir_option)))
        self.assertFalse(cli.option_was_set(
            'authenticator', cli.flag_default('authenticator')))

    def test_encode_revocation_reason(self):
        for reason, code in constants.REVOCATION_REASONS.items():
            namespace = self.parse(['--reason', reason])
            self.assertEqual(namespace.reason, code)
        for reason, code in constants.REVOCATION_REASONS.items():
            namespace = self.parse(['--reason', reason.upper()])
            self.assertEqual(namespace.reason, code)

    def test_force_interactive(self):
        self.assertRaises(
            errors.Error, self.parse, "renew --force-interactive".split())
        self.assertRaises(
            errors.Error, self.parse, "-n --force-interactive".split())

    def test_deploy_hook_conflict(self):
        with mock.patch("certbot._internal.cli.sys.stderr"):
            self.assertRaises(SystemExit, self.parse,
                              "--renew-hook foo --deploy-hook bar".split())

    def test_deploy_hook_matches_renew_hook(self):
        value = "foo"
        namespace = self.parse(["--renew-hook", value,
                                "--deploy-hook", value,
                                "--disable-hook-validation"])
        self.assertEqual(namespace.deploy_hook, value)
        self.assertEqual(namespace.renew_hook, value)

    def test_deploy_hook_sets_renew_hook(self):
        value = "foo"
        namespace = self.parse(
            ["--deploy-hook", value, "--disable-hook-validation"])
        self.assertEqual(namespace.deploy_hook, value)
        self.assertEqual(namespace.renew_hook, value)

    def test_renew_hook_conflict(self):
        with mock.patch("certbot._internal.cli.sys.stderr"):
            self.assertRaises(SystemExit, self.parse,
                              "--deploy-hook foo --renew-hook bar".split())

    def test_renew_hook_matches_deploy_hook(self):
        value = "foo"
        namespace = self.parse(["--deploy-hook", value,
                                "--renew-hook", value,
                                "--disable-hook-validation"])
        self.assertEqual(namespace.deploy_hook, value)
        self.assertEqual(namespace.renew_hook, value)

    def test_renew_hook_does_not_set_renew_hook(self):
        value = "foo"
        namespace = self.parse(
            ["--renew-hook", value, "--disable-hook-validation"])
        self.assertEqual(namespace.deploy_hook, None)
        self.assertEqual(namespace.renew_hook, value)

    def test_max_log_backups_error(self):
        with mock.patch('certbot._internal.cli.sys.stderr'):
            self.assertRaises(
                SystemExit, self.parse, "--max-log-backups foo".split())
            self.assertRaises(
                SystemExit, self.parse, "--max-log-backups -42".split())

    def test_max_log_backups_success(self):
        value = "42"
        namespace = self.parse(["--max-log-backups", value])
        self.assertEqual(namespace.max_log_backups, int(value))

    def test_unchanging_defaults(self):
        namespace = self.parse([])
        self.assertEqual(namespace.domains, [])
        self.assertEqual(namespace.pref_challs, [])

        namespace.pref_challs = [challenges.HTTP01.typ]
        namespace.domains = ['example.com']

        namespace = self.parse([])
        self.assertEqual(namespace.domains, [])
        self.assertEqual(namespace.pref_challs, [])

    def test_no_directory_hooks_set(self):
        self.assertFalse(self.parse(["--no-directory-hooks"]).directory_hooks)

    def test_no_directory_hooks_unset(self):
        self.assertTrue(self.parse([]).directory_hooks)

    def test_delete_after_revoke(self):
        namespace = self.parse(["--delete-after-revoke"])
        self.assertTrue(namespace.delete_after_revoke)

    def test_delete_after_revoke_default(self):
        namespace = self.parse([])
        self.assertEqual(namespace.delete_after_revoke, None)

    def test_no_delete_after_revoke(self):
        namespace = self.parse(["--no-delete-after-revoke"])
        self.assertFalse(namespace.delete_after_revoke)

    def test_allow_subset_with_wildcard(self):
        self.assertRaises(errors.Error, self.parse,
                          "--allow-subset-of-names -d *.example.org".split())

    def test_route53_no_revert(self):
        for help_flag in ['-h', '--help']:
            for topic in ['all', 'plugins', 'dns-route53']:
                self.assertFalse('certbot-route53:auth' in self._help_output([help_flag, topic]))

    def test_no_permissions_check_accepted(self):
        namespace = self.parse(["--no-permissions-check"])
        self.assertTrue(namespace.no_permissions_check)


class DefaultTest(unittest.TestCase):
    """Tests for certbot._internal.cli._Default."""


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

    def test_deploy_hook(self):
        self.assertTrue(_call_set_by_cli(
            'renew_hook', '--deploy-hook foo'.split(), 'renew'))

    def test_webroot_map(self):
        args = '-w /var/www/html -d example.com'.split()
        verb = 'renew'
        self.assertTrue(_call_set_by_cli('webroot_map', args, verb))

    def test_report_config_interaction_str(self):
        cli.report_config_interaction('manual_public_ip_logging_ok',
                                      'manual_auth_hook')
        cli.report_config_interaction('manual_auth_hook', 'manual')

        self._test_report_config_interaction_common()

    def test_report_config_interaction_iterable(self):
        cli.report_config_interaction(('manual_public_ip_logging_ok',),
                                      ('manual_auth_hook',))
        cli.report_config_interaction(('manual_auth_hook',), ('manual',))

        self._test_report_config_interaction_common()

    def _test_report_config_interaction_common(self):
        """Tests implied interaction between manual flags.

        --manual implies --manual-auth-hook which implies
        --manual-public-ip-logging-ok. These interactions don't actually
        exist in the client, but are used here for testing purposes.

        """

        args = ['--manual']
        verb = 'renew'
        for v in ('manual', 'manual_auth_hook', 'manual_public_ip_logging_ok'):
            self.assertTrue(_call_set_by_cli(v, args, verb))

        # https://github.com/python/mypy/issues/2087
        cli.set_by_cli.detector = None  # type: ignore

        args = ['--manual-auth-hook', 'command']
        for v in ('manual_auth_hook', 'manual_public_ip_logging_ok'):
            self.assertTrue(_call_set_by_cli(v, args, verb))

        self.assertFalse(_call_set_by_cli('manual', args, verb))


def _call_set_by_cli(var, args, verb):
    with mock.patch('certbot._internal.cli.helpful_parser') as mock_parser:
        with test_util.patch_get_utility():
            mock_parser.args = args
            mock_parser.verb = verb
            return cli.set_by_cli(var)


if __name__ == '__main__':
    unittest.main()  # pragma: no cover
