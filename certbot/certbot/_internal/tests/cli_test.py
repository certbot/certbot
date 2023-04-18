"""Tests for certbot._internal.cli."""
import argparse
import copy
from importlib import reload as reload_module
import io
import sys
import tempfile
import unittest
from unittest import mock

import pytest

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
            # The read-only filesystem introduced with macOS Catalina can break
            # code using relative paths below. See
            # https://bugs.python.org/issue38295 for another example of this.
            # Eliminating any possible symlinks in self.tempdir before passing
            # it to os.path.relpath solves the problem. This is done by calling
            # filesystem.realpath which removes any symlinks in the path on
            # POSIX systems.
            real_path = filesystem.realpath(os.path.join(self.tempdir, 'foo'))
            relative_path = os.path.relpath(real_path)
            with pytest.raises(argparse.ArgumentTypeError):
                cli.read_file(relative_path)

            test_contents = b'bar\n'
            with open(relative_path, 'wb') as f:
                f.write(test_contents)

            path, contents = cli.read_file(relative_path)
            assert path == os.path.abspath(path)
            assert contents == test_contents
        finally:
            os.chdir(curr_dir)


class FlagDefaultTest(unittest.TestCase):
    """Tests cli.flag_default"""

    def test_default_directories(self):
        if os.name != 'nt':
            assert cli.flag_default('config_dir') == '/etc/letsencrypt'
            assert cli.flag_default('work_dir') == '/var/lib/letsencrypt'
            assert cli.flag_default('logs_dir') == '/var/log/letsencrypt'
        else:
            assert cli.flag_default('config_dir') == 'C:\\Certbot'
            assert cli.flag_default('work_dir') == 'C:\\Certbot\\lib'
            assert cli.flag_default('logs_dir') == 'C:\\Certbot\\log'


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
        """Mocks certbot._internal.display.obj.get_display and calls _unmocked_parse."""
        with test_util.patch_display_util():
            return ParseTest._unmocked_parse(*args, **kwargs)

    def _help_output(self, args):
        "Run a command, and return the output string for scrutiny"

        output = io.StringIO()

        def write_msg(message, *args, **kwargs): # pylint: disable=missing-docstring,unused-argument
            output.write(message)

        with mock.patch('certbot._internal.main.sys.stdout', new=output):
            with test_util.patch_display_util() as mock_get_utility:
                mock_get_utility().notification.side_effect = write_msg
                with mock.patch('certbot._internal.main.sys.stderr'):
                    with pytest.raises(SystemExit):
                        self._unmocked_parse(args, output)

        return output.getvalue()

    @mock.patch("certbot._internal.cli.helpful.flag_default")
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
            assert namespace.domains == []
            with open(tmp_config.name, 'w') as file_h:
                file_h.write("domains = example.com")
            namespace = self.parse(["certonly"])
            assert namespace.domains == ["example.com"]
            namespace = self.parse(["renew"])
            assert namespace.domains == []

    def test_no_args(self):
        namespace = self.parse([])
        for d in ('config_dir', 'logs_dir', 'work_dir'):
            assert getattr(namespace, d) == cli.flag_default(d)

    def test_install_abspath(self):
        cert = 'cert'
        key = 'key'
        chain = 'chain'
        fullchain = 'fullchain'

        with mock.patch('certbot._internal.main.install'):
            namespace = self.parse(['install', '--cert-path', cert,
                                    '--key-path', 'key', '--chain-path',
                                    'chain', '--fullchain-path', 'fullchain'])

        assert namespace.cert_path == os.path.abspath(cert)
        assert namespace.key_path == os.path.abspath(key)
        assert namespace.chain_path == os.path.abspath(chain)
        assert namespace.fullchain_path == os.path.abspath(fullchain)

    def test_help(self):
        self._help_output(['--help'])  # assert SystemExit is raised here
        out = self._help_output(['--help', 'all'])
        assert "--configurator" in out
        assert "how a certificate is deployed" in out
        assert "--webroot-path" in out
        assert "--text" not in out
        assert "%s" not in out
        assert "{0}" not in out
        assert "--renew-hook" not in out

        out = self._help_output(['-h', 'nginx'])
        if "nginx" in PLUGINS:
            # may be false while building distributions without plugins
            assert "--nginx-ctl" in out
        assert "--webroot-path" not in out
        assert "--checkpoints" not in out

        out = self._help_output(['-h'])
        if "nginx" in PLUGINS:
            assert "Use the Nginx plugin" in out
        else:
            assert "(the certbot nginx plugin is not" in out

        out = self._help_output(['--help', 'plugins'])
        assert "--webroot-path" not in out
        assert "--prepare" in out
        assert '"plugins" subcommand' in out

        # test multiple topics
        out = self._help_output(['-h', 'renew'])
        assert "--keep" in out
        out = self._help_output(['-h', 'automation'])
        assert "--keep" in out
        out = self._help_output(['-h', 'revoke'])
        assert "--keep" not in out

        out = self._help_output(['--help', 'install'])
        assert "--cert-path" in out
        assert "--key-path" in out

        out = self._help_output(['--help', 'revoke'])
        assert "--cert-path" in out
        assert "--key-path" in out
        assert "--reason" in out
        assert "--delete-after-revoke" in out
        assert "--no-delete-after-revoke" in out

        out = self._help_output(['-h', 'register'])
        assert "--cert-path" not in out
        assert "--key-path" not in out

        out = self._help_output(['-h'])
        assert cli.SHORT_USAGE in out
        assert cli.COMMAND_OVERVIEW[:100] in out
        assert "%s" not in out
        assert "{0}" not in out

    def test_help_no_dashes(self):
        self._help_output(['help'])  # assert SystemExit is raised here

        out = self._help_output(['help', 'all'])
        assert "--configurator" in out
        assert "how a certificate is deployed" in out
        assert "--webroot-path" in out
        assert "--text" not in out
        assert "%s" not in out
        assert "{0}" not in out

        out = self._help_output(['help', 'install'])
        assert "--cert-path" in out
        assert "--key-path" in out

        out = self._help_output(['help', 'revoke'])
        assert "--cert-path" in out
        assert "--key-path" in out

    def test_parse_domains(self):
        short_args = ['-d', 'example.com']
        namespace = self.parse(short_args)
        assert namespace.domains == ['example.com']

        short_args = ['-d', 'trailing.period.com.']
        namespace = self.parse(short_args)
        assert namespace.domains == ['trailing.period.com']

        short_args = ['-d', 'example.com,another.net,third.org,example.com']
        namespace = self.parse(short_args)
        assert namespace.domains == ['example.com', 'another.net',
                                             'third.org']

        long_args = ['--domains', 'example.com']
        namespace = self.parse(long_args)
        assert namespace.domains == ['example.com']

        long_args = ['--domains', 'trailing.period.com.']
        namespace = self.parse(long_args)
        assert namespace.domains == ['trailing.period.com']

        long_args = ['--domains', 'example.com,another.net,example.com']
        namespace = self.parse(long_args)
        assert namespace.domains == ['example.com', 'another.net']

    def test_preferred_challenges(self):
        short_args = ['--preferred-challenges', 'http, dns']
        namespace = self.parse(short_args)

        expected = [challenges.HTTP01.typ, challenges.DNS01.typ]
        assert namespace.pref_challs == expected

        short_args = ['--preferred-challenges', 'jumping-over-the-moon']
        # argparse.ArgumentError makes argparse print more information
        # to stderr and call sys.exit()
        with mock.patch('sys.stderr'):
            with pytest.raises(SystemExit):
                self.parse(short_args)

    def test_server_flag(self):
        namespace = self.parse('--server example.com'.split())
        assert namespace.server == 'example.com'

    def test_must_staple_flag(self):
        short_args = ['--must-staple']
        namespace = self.parse(short_args)
        assert namespace.must_staple is True
        assert namespace.staple is True

    def _check_server_conflict_message(self, parser_args, conflicting_args):
        try:
            self.parse(parser_args)
            self.fail(  # pragma: no cover
                "The following flags didn't conflict with "
                '--server: {0}'.format(', '.join(conflicting_args)))
        except errors.Error as error:
            assert '--server' in str(error)
            for arg in conflicting_args:
                assert arg in str(error)

    def test_staging_flag(self):
        short_args = ['--staging']
        namespace = self.parse(short_args)
        assert namespace.staging is True
        assert namespace.server == constants.STAGING_URI

        short_args += '--server example.com'.split()
        self._check_server_conflict_message(short_args, '--staging')

    def _assert_dry_run_flag_worked(self, namespace, existing_account):
        assert namespace.dry_run is True
        assert namespace.break_my_certs is True
        assert namespace.staging is True
        assert namespace.server == constants.STAGING_URI

        if existing_account:
            assert namespace.tos is True
            assert namespace.register_unsafely_without_email is True
        else:
            assert namespace.tos is False
            assert namespace.register_unsafely_without_email is False

    def test_dry_run_flag(self):
        config_dir = tempfile.mkdtemp()
        short_args = '--dry-run --config-dir {0}'.format(config_dir).split()
        with pytest.raises(errors.Error):
            self.parse(short_args)

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
        assert self.parse(short_args + ['--server', 'example.com']).server == \
                         'example.com'

        # `--dry-run --server STAGING_URI` should emit STAGING_URI
        assert self.parse(short_args + ['--server', constants.STAGING_URI]).server == \
                         constants.STAGING_URI

        # `--dry-run --server LIVE` should emit STAGING_URI
        assert self.parse(short_args + ['--server', cli.flag_default("server")]).server == \
                         constants.STAGING_URI

        # `--dry-run --server example.com --staging` should emit an error
        conflicts = ['--staging']
        self._check_server_conflict_message(short_args + ['--server', 'example.com', '--staging'],
                                            conflicts)

    def test_option_was_set(self):
        key_size_option = 'rsa_key_size'
        key_size_value = cli.flag_default(key_size_option)
        self.parse('--rsa-key-size {0}'.format(key_size_value).split())

        assert cli.option_was_set(key_size_option, key_size_value) is True
        assert cli.option_was_set('no_verify_ssl', True) is True

        config_dir_option = 'config_dir'
        assert not cli.option_was_set(
            config_dir_option, cli.flag_default(config_dir_option))
        assert not cli.option_was_set(
            'authenticator', cli.flag_default('authenticator'))

    def test_ecdsa_key_option(self):
        elliptic_curve_option = 'elliptic_curve'
        elliptic_curve_option_value = cli.flag_default(elliptic_curve_option)
        self.parse('--elliptic-curve {0}'.format(elliptic_curve_option_value).split())
        assert cli.option_was_set(elliptic_curve_option, elliptic_curve_option_value) is True

    def test_invalid_key_type(self):
        key_type_option = 'key_type'
        key_type_value = cli.flag_default(key_type_option)
        self.parse('--key-type {0}'.format(key_type_value).split())
        assert cli.option_was_set(key_type_option, key_type_value) is True

        with pytest.raises(SystemExit):
            self.parse("--key-type foo")

    def test_encode_revocation_reason(self):
        for reason, code in constants.REVOCATION_REASONS.items():
            namespace = self.parse(['--reason', reason])
            assert namespace.reason == code
        for reason, code in constants.REVOCATION_REASONS.items():
            namespace = self.parse(['--reason', reason.upper()])
            assert namespace.reason == code

    def test_force_interactive(self):
        with pytest.raises(errors.Error):
            self.parse("renew --force-interactive".split())
        with pytest.raises(errors.Error):
            self.parse("-n --force-interactive".split())

    def test_deploy_hook_conflict(self):
        with mock.patch("certbot._internal.cli.sys.stderr"):
            with pytest.raises(SystemExit):
                self.parse("--renew-hook foo --deploy-hook bar".split())

    def test_deploy_hook_matches_renew_hook(self):
        value = "foo"
        namespace = self.parse(["--renew-hook", value,
                                "--deploy-hook", value,
                                "--disable-hook-validation"])
        assert namespace.deploy_hook == value
        assert namespace.renew_hook == value

    def test_deploy_hook_sets_renew_hook(self):
        value = "foo"
        namespace = self.parse(
            ["--deploy-hook", value, "--disable-hook-validation"])
        assert namespace.deploy_hook == value
        assert namespace.renew_hook == value

    def test_renew_hook_conflict(self):
        with mock.patch("certbot._internal.cli.sys.stderr"):
            with pytest.raises(SystemExit):
                self.parse("--deploy-hook foo --renew-hook bar".split())

    def test_renew_hook_matches_deploy_hook(self):
        value = "foo"
        namespace = self.parse(["--deploy-hook", value,
                                "--renew-hook", value,
                                "--disable-hook-validation"])
        assert namespace.deploy_hook == value
        assert namespace.renew_hook == value

    def test_renew_hook_does_not_set_renew_hook(self):
        value = "foo"
        namespace = self.parse(
            ["--renew-hook", value, "--disable-hook-validation"])
        assert namespace.deploy_hook is None
        assert namespace.renew_hook == value

    def test_max_log_backups_error(self):
        with mock.patch('certbot._internal.cli.sys.stderr'):
            with pytest.raises(SystemExit):
                self.parse("--max-log-backups foo".split())
            with pytest.raises(SystemExit):
                self.parse("--max-log-backups -42".split())

    def test_max_log_backups_success(self):
        value = "42"
        namespace = self.parse(["--max-log-backups", value])
        assert namespace.max_log_backups == int(value)

    def test_unchanging_defaults(self):
        namespace = self.parse([])
        assert namespace.domains == []
        assert namespace.pref_challs == []

        namespace.pref_challs = [challenges.HTTP01.typ]
        namespace.domains = ['example.com']

        namespace = self.parse([])
        assert namespace.domains == []
        assert namespace.pref_challs == []

    def test_no_directory_hooks_set(self):
        assert not self.parse(["--no-directory-hooks"]).directory_hooks

    def test_no_directory_hooks_unset(self):
        assert self.parse([]).directory_hooks is True

    def test_delete_after_revoke(self):
        namespace = self.parse(["--delete-after-revoke"])
        assert namespace.delete_after_revoke is True

    def test_delete_after_revoke_default(self):
        namespace = self.parse([])
        assert namespace.delete_after_revoke is None

    def test_no_delete_after_revoke(self):
        namespace = self.parse(["--no-delete-after-revoke"])
        assert namespace.delete_after_revoke is False

    def test_allow_subset_with_wildcard(self):
        with pytest.raises(errors.Error):
            self.parse("--allow-subset-of-names -d *.example.org".split())

    def test_route53_no_revert(self):
        for help_flag in ['-h', '--help']:
            for topic in ['all', 'plugins', 'dns-route53']:
                assert 'certbot-route53:auth' not in self._help_output([help_flag, topic])


class DefaultTest(unittest.TestCase):
    """Tests for certbot._internal.cli._Default."""


    def setUp(self):
        # pylint: disable=protected-access
        self.default1 = cli._Default()
        self.default2 = cli._Default()

    def test_boolean(self):
        assert bool(self.default1) is False
        assert bool(self.default2) is False

    def test_equality(self):
        assert self.default1 == self.default2

    def test_hash(self):
        assert hash(self.default1) == hash(self.default2)


class SetByCliTest(unittest.TestCase):
    """Tests for certbot.set_by_cli and related functions."""


    def setUp(self):
        reload_module(cli)

    def test_deploy_hook(self):
        assert _call_set_by_cli(
            'renew_hook', '--deploy-hook foo'.split(), 'renew')

    def test_webroot_map(self):
        args = '-w /var/www/html -d example.com'.split()
        verb = 'renew'
        assert _call_set_by_cli('webroot_map', args, verb) is True


def _call_set_by_cli(var, args, verb):
    with mock.patch('certbot._internal.cli.helpful_parser') as mock_parser:
        with test_util.patch_display_util():
            mock_parser.args = args
            mock_parser.verb = verb
            return cli.set_by_cli(var)


if __name__ == '__main__':
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover
