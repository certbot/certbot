"""Tests for certbot.main."""
# pylint: disable=too-many-lines
from __future__ import print_function

import itertools
import mock
import os
import shutil
import traceback
import unittest
import datetime
import pytz

import six
from six.moves import reload_module  # pylint: disable=import-error

from acme import jose

from certbot import account
from certbot import cli
from certbot import constants
from certbot import configuration
from certbot import crypto_util
from certbot import errors
from certbot import main
from certbot import util

from certbot.plugins import disco
from certbot.plugins import manual

import certbot.tests.util as test_util

CERT_PATH = test_util.vector_path('cert_512.pem')
CERT = test_util.vector_path('cert_512.pem')
CSR = test_util.vector_path('csr_512.der')
KEY = test_util.vector_path('rsa256_key.pem')
JWK = jose.JWKRSA.load(test_util.load_vector('rsa512_key.pem'))
RSA2048_KEY_PATH = test_util.vector_path('rsa2048_key.pem')
SS_CERT_PATH = test_util.vector_path('cert_2048.pem')


class TestHandleIdenticalCerts(unittest.TestCase):
    """Test for certbot.main._handle_identical_cert_request"""
    def test_handle_identical_cert_request_pending(self):
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
            mock.patch('certbot.main._get_and_save_cert'),
            mock.patch('certbot.main.display_ops.success_installation'),
            mock.patch('certbot.main.display_ops.success_renewal'),
            mock.patch('certbot.main._init_le_client'),
            mock.patch('certbot.main._suggest_donation_if_appropriate'),
            mock.patch('certbot.main._report_new_cert'),
            mock.patch('certbot.main._find_cert')]

        self.mock_auth = self.patches[0].start()
        self.mock_success_installation = self.patches[1].start()
        self.mock_success_renewal = self.patches[2].start()
        self.mock_init = self.patches[3].start()
        self.mock_suggest_donation = self.patches[4].start()
        self.mock_report_cert = self.patches[5].start()
        self.mock_find_cert = self.patches[6].start()

    def tearDown(self):
        for patch in self.patches:
            patch.stop()

    def _call(self):
        args = '-a webroot -i null -d {0}'.format(self.domain).split()
        plugins = disco.PluginsRegistry.find_all()
        config = configuration.NamespaceConfig(
            cli.prepare_and_parse_args(plugins, args))

        from certbot.main import run
        run(config, plugins)

    def test_newcert_success(self):
        self.mock_auth.return_value = mock.Mock()
        self.mock_find_cert.return_value = True, None
        self._call()
        self.mock_success_installation.assert_called_once_with([self.domain])

    def test_reinstall_success(self):
        self.mock_auth.return_value = mock.Mock()
        self.mock_find_cert.return_value = False, mock.Mock()
        self._call()
        self.mock_success_installation.assert_called_once_with([self.domain])

    def test_renewal_success(self):
        self.mock_auth.return_value = mock.Mock()
        self.mock_find_cert.return_value = True, mock.Mock()
        self._call()
        self.mock_success_renewal.assert_called_once_with([self.domain])


class CertonlyTest(unittest.TestCase):
    """Tests for certbot.main.certonly."""

    def setUp(self):
        self.get_utility_patch = test_util.patch_get_utility()
        self.mock_get_utility = self.get_utility_patch.start()

    def tearDown(self):
        self.get_utility_patch.stop()

    def _call(self, args):
        plugins = disco.PluginsRegistry.find_all()
        config = configuration.NamespaceConfig(
            cli.prepare_and_parse_args(plugins, args))

        with mock.patch('certbot.main._init_le_client') as mock_init:
            with mock.patch('certbot.main._suggest_donation_if_appropriate'):
                main.certonly(config, plugins)

        return mock_init()  # returns the client

    @mock.patch('certbot.main._find_cert')
    @mock.patch('certbot.main._get_and_save_cert')
    @mock.patch('certbot.main._report_new_cert')
    def test_no_reinstall_text_pause(self, unused_report, mock_auth,
        mock_find_cert):
        mock_notification = self.mock_get_utility().notification
        mock_notification.side_effect = self._assert_no_pause
        mock_auth.return_value = mock.Mock()
        mock_find_cert.return_value = False, None
        self._call('certonly --webroot -d example.com'.split())

    def _assert_no_pause(self, message, pause=True):
        # pylint: disable=unused-argument
        self.assertFalse(pause)

    @mock.patch('certbot.cert_manager.lineage_for_certname')
    @mock.patch('certbot.cert_manager.domains_for_certname')
    @mock.patch('certbot.renewal.renew_cert')
    @mock.patch('certbot.main._report_new_cert')
    def test_find_lineage_for_domains_and_certname(self, mock_report_cert,
        mock_renew_cert, mock_domains, mock_lineage):
        domains = ['example.com', 'test.org']
        mock_domains.return_value = domains
        mock_lineage.names.return_value = domains
        self._call(('certonly --webroot -d example.com -d test.org '
            '--cert-name example.com').split())
        self.assertTrue(mock_lineage.call_count == 1)
        self.assertTrue(mock_domains.call_count == 1)
        self.assertTrue(mock_renew_cert.call_count == 1)
        self.assertTrue(mock_report_cert.call_count == 1)

        # user confirms updating lineage with new domains
        self._call(('certonly --webroot -d example.com -d test.com '
            '--cert-name example.com').split())
        self.assertTrue(mock_lineage.call_count == 2)
        self.assertTrue(mock_domains.call_count == 2)
        self.assertTrue(mock_renew_cert.call_count == 2)
        self.assertTrue(mock_report_cert.call_count == 2)

        # error in _ask_user_to_confirm_new_names
        self.mock_get_utility().yesno.return_value = False
        self.assertRaises(errors.ConfigurationError, self._call,
            ('certonly --webroot -d example.com -d test.com --cert-name example.com').split())

    @mock.patch('certbot.cert_manager.domains_for_certname')
    @mock.patch('certbot.display.ops.choose_names')
    @mock.patch('certbot.cert_manager.lineage_for_certname')
    @mock.patch('certbot.main._report_new_cert')
    def test_find_lineage_for_domains_new_certname(self, mock_report_cert,
        mock_lineage, mock_choose_names, mock_domains_for_certname):
        mock_lineage.return_value = None

        # no lineage with this name but we specified domains so create a new cert
        self._call(('certonly --webroot -d example.com -d test.com '
            '--cert-name example.com').split())
        self.assertTrue(mock_lineage.call_count == 1)
        self.assertTrue(mock_report_cert.call_count == 1)

        # no lineage with this name and we didn't give domains
        mock_choose_names.return_value = ["somename"]
        mock_domains_for_certname.return_value = None
        self._call(('certonly --webroot --cert-name example.com').split())
        self.assertTrue(mock_choose_names.called)

class FindDomainsOrCertnameTest(unittest.TestCase):
    """Tests for certbot.main._find_domains_or_certname."""

    @mock.patch('certbot.display.ops.choose_names')
    def test_display_ops(self, mock_choose_names):
        mock_config = mock.Mock(domains=None, certname=None)
        mock_choose_names.return_value = "domainname"
        # pylint: disable=protected-access
        self.assertEqual(main._find_domains_or_certname(mock_config, None),
            ("domainname", None))

    @mock.patch('certbot.display.ops.choose_names')
    def test_no_results(self, mock_choose_names):
        mock_config = mock.Mock(domains=None, certname=None)
        mock_choose_names.return_value = []
        # pylint: disable=protected-access
        self.assertRaises(errors.Error, main._find_domains_or_certname, mock_config, None)

    @mock.patch('certbot.cert_manager.domains_for_certname')
    def test_grab_domains(self, mock_domains):
        mock_config = mock.Mock(domains=None, certname="one.com")
        mock_domains.return_value = ["one.com", "two.com"]
        # pylint: disable=protected-access
        self.assertEqual(main._find_domains_or_certname(mock_config, None),
            (["one.com", "two.com"], "one.com"))


class RevokeTest(test_util.TempDirTestCase):
    """Tests for certbot.main.revoke."""

    def setUp(self):
        super(RevokeTest, self).setUp()

        shutil.copy(CERT_PATH, self.tempdir)
        self.tmp_cert_path = os.path.abspath(os.path.join(self.tempdir,
            'cert_512.pem'))

        self.patches = [
            mock.patch('acme.client.Client', autospec=True),
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
        self.acc = Account(self.regr, JWK, self.meta)

        self.mock_determine_account.return_value = (self.acc, None)

    def tearDown(self):
        super(RevokeTest, self).tearDown()

        for patch in self.patches:
            patch.stop()

    def _call(self, extra_args=""):
        args = 'revoke --cert-path={0} ' + extra_args
        args = args.format(self.tmp_cert_path).split()
        plugins = disco.PluginsRegistry.find_all()
        config = configuration.NamespaceConfig(
            cli.prepare_and_parse_args(plugins, args))

        from certbot.main import revoke
        revoke(config, plugins)

    @mock.patch('certbot.main._delete_if_appropriate')
    @mock.patch('certbot.main.client.acme_client')
    def test_revoke_with_reason(self, mock_acme_client,
            mock_delete_if_appropriate):
        mock_delete_if_appropriate.return_value = False
        mock_revoke = mock_acme_client.Client().revoke
        expected = []
        for reason, code in constants.REVOCATION_REASONS.items():
            self._call("--reason " + reason)
            expected.append(mock.call(mock.ANY, code))
            self._call("--reason " + reason.upper())
            expected.append(mock.call(mock.ANY, code))
        self.assertEqual(expected, mock_revoke.call_args_list)

    @mock.patch('certbot.main._delete_if_appropriate')
    def test_revocation_success(self, mock_delete_if_appropriate):
        self._call()
        mock_delete_if_appropriate.return_value = False
        self.mock_success_revoke.assert_called_once_with(self.tmp_cert_path)

    def test_revocation_error(self):
        from acme import errors as acme_errors
        self.mock_acme_client.side_effect = acme_errors.ClientError()
        self.assertRaises(acme_errors.ClientError, self._call)
        self.mock_success_revoke.assert_not_called()

    @mock.patch('certbot.main._delete_if_appropriate')
    @mock.patch('certbot.cert_manager.delete')
    @test_util.patch_get_utility()
    def test_revocation_with_prompt(self, mock_get_utility,
            mock_delete, mock_delete_if_appropriate):
        mock_get_utility().yesno.return_value = False
        mock_delete_if_appropriate.return_value = False
        self._call()
        self.assertFalse(mock_delete.called)

class DeleteIfAppropriateTest(unittest.TestCase):
    """Tests for certbot.main._delete_if_appropriate """

    def setUp(self):
        self.config = mock.Mock()
        self.config.namespace = mock.Mock()
        self.config.namespace.noninteractive_mode = False

    def _call(self, mock_config):
        from certbot.main import _delete_if_appropriate
        _delete_if_appropriate(mock_config)

    @mock.patch('certbot.cert_manager.delete')
    @test_util.patch_get_utility()
    def test_delete_opt_out(self, mock_get_utility, mock_delete):
        util_mock = mock_get_utility()
        util_mock.yesno.return_value = False
        self._call(self.config)
        mock_delete.assert_not_called()

    # pylint: disable=too-many-arguments
    @mock.patch('certbot.storage.renewal_file_for_certname')
    @mock.patch('certbot.cert_manager.delete')
    @mock.patch('certbot.cert_manager.match_and_check_overlaps')
    @mock.patch('certbot.storage.full_archive_path')
    @mock.patch('certbot.cert_manager.cert_path_to_lineage')
    @test_util.patch_get_utility()
    def test_overlapping_archive_dirs(self, mock_get_utility,
            mock_cert_path_to_lineage, mock_archive,
            mock_match_and_check_overlaps, mock_delete,
            mock_renewal_file_for_certname):
        # pylint: disable = unused-argument
        config = self.config
        config.cert_path = "/some/reasonable/path"
        config.certname = ""
        mock_cert_path_to_lineage.return_value = "example.com"
        mock_match_and_check_overlaps.side_effect = errors.OverlappingMatchFound()
        self._call(config)
        mock_delete.assert_not_called()

    # pylint: disable=too-many-arguments
    @mock.patch('certbot.storage.renewal_file_for_certname')
    @mock.patch('certbot.cert_manager.match_and_check_overlaps')
    @mock.patch('certbot.storage.full_archive_path')
    @mock.patch('certbot.cert_manager.delete')
    @mock.patch('certbot.storage.cert_path_for_cert_name')
    @test_util.patch_get_utility()
    def test_cert_name_only(self, mock_get_utility,
            mock_cert_path_for_cert_name, mock_delete, mock_archive,
            mock_overlapping_archive_dirs, mock_renewal_file_for_certname):
        # pylint: disable = unused-argument
        config = self.config
        config.certname = "example.com"
        config.cert_path = ""
        mock_cert_path_for_cert_name.return_value = "/some/reasonable/path"
        mock_overlapping_archive_dirs.return_value = False
        self._call(config)
        mock_delete.assert_called_once()

    # pylint: disable=too-many-arguments
    @mock.patch('certbot.storage.renewal_file_for_certname')
    @mock.patch('certbot.cert_manager.match_and_check_overlaps')
    @mock.patch('certbot.storage.full_archive_path')
    @mock.patch('certbot.cert_manager.delete')
    @mock.patch('certbot.cert_manager.cert_path_to_lineage')
    @test_util.patch_get_utility()
    def test_cert_path_only(self, mock_get_utility,
            mock_cert_path_to_lineage, mock_delete, mock_archive,
            mock_overlapping_archive_dirs, mock_renewal_file_for_certname):
        # pylint: disable = unused-argument
        config = self.config
        config.cert_path = "/some/reasonable/path"
        config.certname = ""
        mock_cert_path_to_lineage.return_value = "example.com"
        mock_overlapping_archive_dirs.return_value = False
        self._call(config)
        mock_delete.assert_called_once()

    # pylint: disable=too-many-arguments
    @mock.patch('certbot.storage.renewal_file_for_certname')
    @mock.patch('certbot.cert_manager.match_and_check_overlaps')
    @mock.patch('certbot.storage.full_archive_path')
    @mock.patch('certbot.cert_manager.cert_path_to_lineage')
    @mock.patch('certbot.cert_manager.delete')
    @test_util.patch_get_utility()
    def test_noninteractive_deletion(self, mock_get_utility, mock_delete,
            mock_cert_path_to_lineage, mock_full_archive_dir,
            mock_match_and_check_overlaps, mock_renewal_file_for_certname):
        # pylint: disable = unused-argument
        config = self.config
        config.namespace.noninteractive_mode = True
        config.cert_path = "/some/reasonable/path"
        config.certname = ""
        mock_cert_path_to_lineage.return_value = "example.com"
        mock_full_archive_dir.return_value = ""
        mock_match_and_check_overlaps.return_value = ""
        self._call(config)
        mock_delete.assert_called_once()

    # pylint: disable=too-many-arguments
    @mock.patch('certbot.storage.renewal_file_for_certname')
    @mock.patch('certbot.cert_manager.match_and_check_overlaps')
    @mock.patch('certbot.storage.full_archive_path')
    @mock.patch('certbot.cert_manager.delete')
    @mock.patch('certbot.cert_manager.cert_path_to_lineage')
    @test_util.patch_get_utility()
    def test_certname_and_cert_path_match(self, mock_get_utility,
            mock_cert_path_to_lineage, mock_delete, mock_archive,
            mock_overlapping_archive_dirs, mock_renewal_file_for_certname):
        # pylint: disable = unused-argument
        config = self.config
        config.certname = "example.com"
        config.cert_path = "/some/reasonable/path"
        mock_cert_path_to_lineage.return_value = config.certname
        mock_overlapping_archive_dirs.return_value = False
        self._call(config)
        mock_delete.assert_called_once()

    # pylint: disable=too-many-arguments
    @mock.patch('certbot.cert_manager.match_and_check_overlaps')
    @mock.patch('certbot.storage.full_archive_path')
    @mock.patch('certbot.cert_manager.delete')
    @mock.patch('certbot.cert_manager.human_readable_cert_info')
    @mock.patch('certbot.storage.RenewableCert')
    @mock.patch('certbot.storage.renewal_file_for_certname')
    @mock.patch('certbot.cert_manager.cert_path_to_lineage')
    @test_util.patch_get_utility()
    def test_certname_and_cert_path_mismatch(self, mock_get_utility,
            mock_cert_path_to_lineage, mock_renewal_file_for_certname,
            mock_RenewableCert, mock_human_readable_cert_info,
            mock_delete, mock_archive, mock_overlapping_archive_dirs):
        # pylint: disable=unused-argument
        config = self.config
        config.certname = "example.com"
        config.cert_path = "/some/reasonable/path"
        mock_cert_path_to_lineage = "something else"
        mock_RenewableCert.return_value = mock.Mock()
        mock_human_readable_cert_info.return_value = ""
        mock_overlapping_archive_dirs.return_value = False
        from certbot.display import util as display_util
        util_mock = mock_get_utility()
        util_mock.menu.return_value = (display_util.OK, 0)
        self._call(config)
        mock_delete.assert_called_once()

    # pylint: disable=too-many-arguments
    @mock.patch('certbot.cert_manager.match_and_check_overlaps')
    @mock.patch('certbot.storage.full_archive_path')
    @mock.patch('certbot.cert_manager.delete')
    @mock.patch('certbot.cert_manager.human_readable_cert_info')
    @mock.patch('certbot.storage.RenewableCert')
    @mock.patch('certbot.storage.renewal_file_for_certname')
    @mock.patch('certbot.cert_manager.cert_path_to_lineage')
    @test_util.patch_get_utility()
    def test_noninteractive_certname_cert_path_mismatch(self, mock_get_utility,
            mock_cert_path_to_lineage, mock_renewal_file_for_certname,
            mock_RenewableCert, mock_human_readable_cert_info,
            mock_delete, mock_archive, mock_overlapping_archive_dirs):
        # pylint: disable=unused-argument
        config = self.config
        config.certname = "example.com"
        config.cert_path = "/some/reasonable/path"
        mock_cert_path_to_lineage.return_value = "some-reasonable-path.com"
        mock_RenewableCert.return_value = mock.Mock()
        mock_human_readable_cert_info.return_value = ""
        mock_overlapping_archive_dirs.return_value = False
        # Test for non-interactive mode
        util_mock = mock_get_utility()
        util_mock.menu.side_effect = errors.MissingCommandlineFlag("Oh no.")
        self.assertRaises(errors.Error, self._call, config)
        mock_delete.assert_not_called()

    @mock.patch('certbot.cert_manager.delete')
    @test_util.patch_get_utility()
    def test_no_certname_or_cert_path(self, mock_get_utility, mock_delete):
        # pylint: disable=unused-argument
        config = self.config
        config.certname = None
        config.cert_path = None
        self.assertRaises(errors.Error, self._call, config)
        mock_delete.assert_not_called()


class DetermineAccountTest(test_util.ConfigTestCase):
    """Tests for certbot.main._determine_account."""

    def setUp(self):
        super(DetermineAccountTest, self).setUp()
        self.config.account = None
        self.config.email = None
        self.config.register_unsafely_without_email = False
        self.accs = [mock.MagicMock(id='x'), mock.MagicMock(id='y')]
        self.account_storage = account.AccountMemoryStorage()
        # For use in saving accounts: fake out the new_authz URL.
        self.mock_client = mock.MagicMock()
        self.mock_client.directory.new_authz = "hi"

    def _call(self):
        # pylint: disable=protected-access
        from certbot.main import _determine_account
        with mock.patch('certbot.main.account.AccountFileStorage') as mock_storage:
            mock_storage.return_value = self.account_storage
            return _determine_account(self.config)

    def test_args_account_set(self):
        self.account_storage.save(self.accs[1], self.mock_client)
        self.config.account = self.accs[1].id
        self.assertEqual((self.accs[1], None), self._call())
        self.assertEqual(self.accs[1].id, self.config.account)
        self.assertTrue(self.config.email is None)

    def test_single_account(self):
        self.account_storage.save(self.accs[0], self.mock_client)
        self.assertEqual((self.accs[0], None), self._call())
        self.assertEqual(self.accs[0].id, self.config.account)
        self.assertTrue(self.config.email is None)

    @mock.patch('certbot.client.display_ops.choose_account')
    def test_multiple_accounts(self, mock_choose_accounts):
        for acc in self.accs:
            self.account_storage.save(acc, self.mock_client)
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


class MainTest(test_util.ConfigTestCase):  # pylint: disable=too-many-public-methods
    """Tests for different commands."""

    def setUp(self):
        super(MainTest, self).setUp()

        os.mkdir(self.config.logs_dir)
        self.standard_args = ['--config-dir', self.config.config_dir,
                              '--work-dir', self.config.work_dir,
                              '--logs-dir', self.config.logs_dir, '--text']

    def tearDown(self):
        # Reset globals in cli
        reload_module(cli)

        super(MainTest, self).tearDown()

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

    def test_version_string_program_name(self):
        toy_out = six.StringIO()
        toy_err = six.StringIO()
        with mock.patch('certbot.main.sys.stdout', new=toy_out):
            with mock.patch('certbot.main.sys.stderr', new=toy_err):
                try:
                    main.main(["--version"])
                except SystemExit:
                    pass
                finally:
                    output = toy_out.getvalue() or toy_err.getvalue()
                    self.assertTrue("certbot" in output, "Output is {0}".format(output))

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
        with mock.patch('certbot.main._get_and_save_cert'):
            with mock.patch('certbot.main.client.acme_from_config_key'):
                args.extend(['--email', 'io@io.is'])
                self._cli_missing_flag(args, "--agree-tos")

    @mock.patch('certbot.main._report_new_cert')
    @mock.patch('certbot.main.client.acme_client.Client')
    @mock.patch('certbot.main._determine_account')
    @mock.patch('certbot.main.client.Client.obtain_and_enroll_certificate')
    @mock.patch('certbot.main._get_and_save_cert')
    def test_user_agent(self, gsc, _obt, det, _client, unused_report):
        # Normally the client is totally mocked out, but here we need more
        # arguments to automate it...
        args = ["--standalone", "certonly", "-m", "none@none.com",
                "-d", "example.com", '--agree-tos'] + self.standard_args
        det.return_value = mock.MagicMock(), None
        gsc.return_value = mock.MagicMock()

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

    @mock.patch('certbot.main.plug_sel.record_chosen_plugins')
    @mock.patch('certbot.main.plug_sel.pick_installer')
    def test_installer_selection(self, mock_pick_installer, _rec):
        self._call(['install', '--domains', 'foo.bar', '--cert-path', 'cert',
                    '--key-path', 'key', '--chain-path', 'chain'])
        self.assertEqual(mock_pick_installer.call_count, 1)

    @mock.patch('certbot.main._report_new_cert')
    @mock.patch('certbot.util.exe_exists')
    def test_configurator_selection(self, mock_exe_exists, unused_report):
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
            with mock.patch("certbot.main._get_and_save_cert") as mock_gsc:
                mock_gsc.return_value = mock.MagicMock()
                self._call(["certonly", "--manual", "-d", "foo.bar"])
                unused_config, auth, unused_installer = mock_init.call_args[0]
                self.assertTrue(isinstance(auth, manual.Authenticator))

        with mock.patch('certbot.main.certonly') as mock_certonly:
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

    @mock.patch('certbot.cert_manager.update_live_symlinks')
    def test_update_symlinks(self, mock_cert_manager):
        self._call_no_clientmock(['update_symlinks'])
        self.assertEqual(1, mock_cert_manager.call_count)

    @mock.patch('certbot.cert_manager.certificates')
    def test_certificates(self, mock_cert_manager):
        self._call_no_clientmock(['certificates'])
        self.assertEqual(1, mock_cert_manager.call_count)

    @mock.patch('certbot.cert_manager.delete')
    def test_delete(self, mock_cert_manager):
        self._call_no_clientmock(['delete'])
        self.assertEqual(1, mock_cert_manager.call_count)

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

        stdout = six.StringIO()
        with test_util.patch_get_utility_with_stdout(stdout=stdout):
            _, stdout, _, _ = self._call(['plugins'], stdout)

        plugins.visible.assert_called_once_with()
        plugins.visible().ifaces.assert_called_once_with(ifaces)
        filtered = plugins.visible().ifaces()
        self.assertEqual(stdout.getvalue().strip(), str(filtered))

    @mock.patch('certbot.main.plugins_disco')
    @mock.patch('certbot.main.cli.HelpfulArgumentParser.determine_help_topics')
    def test_plugins_no_args_unprivileged(self, _det, mock_disco):
        ifaces = []
        plugins = mock_disco.PluginsRegistry.find_all()

        def throw_error(directory, mode, uid, strict):
            """Raises error.Error."""
            _, _, _, _ = directory, mode, uid, strict
            raise errors.Error()

        stdout = six.StringIO()
        with mock.patch('certbot.util.set_up_core_dir') as mock_set_up_core_dir:
            with test_util.patch_get_utility_with_stdout(stdout=stdout):
                mock_set_up_core_dir.side_effect = throw_error
                _, stdout, _, _ = self._call(['plugins'], stdout)

        plugins.visible.assert_called_once_with()
        plugins.visible().ifaces.assert_called_once_with(ifaces)
        filtered = plugins.visible().ifaces()
        self.assertEqual(stdout.getvalue().strip(), str(filtered))

    @mock.patch('certbot.main.plugins_disco')
    @mock.patch('certbot.main.cli.HelpfulArgumentParser.determine_help_topics')
    def test_plugins_init(self, _det, mock_disco):
        ifaces = []
        plugins = mock_disco.PluginsRegistry.find_all()

        stdout = six.StringIO()
        with test_util.patch_get_utility_with_stdout(stdout=stdout):
            _, stdout, _, _ = self._call(['plugins', '--init'], stdout)

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

        stdout = six.StringIO()
        with test_util.patch_get_utility_with_stdout(stdout=stdout):
            _, stdout, _, _ = self._call(['plugins', '--init', '--prepare'], stdout)

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

        with mock.patch('certbot.main.certonly') as mock_certonly:
            self._call(['certonly', '--cert-path', cert, '--key-path', 'key',
                        '--chain-path', 'chain',
                        '--fullchain-path', 'fullchain'])

        config, unused_plugins = mock_certonly.call_args[0]
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
                test_util.vector_path('csr-nonames_512.pem')).split())

    def test_csr_with_inconsistent_domains(self):
        self.assertRaises(
            errors.Error, self._call,
            'certonly -d example.org --csr {0}'.format(CSR).split())

    def _certonly_new_request_common(self, mock_client, args=None):
        with mock.patch('certbot.main._find_lineage_for_domains_and_certname') as mock_renewal:
            mock_renewal.return_value = ("newcert", None)
            with mock.patch('certbot.main._init_le_client') as mock_init:
                mock_init.return_value = mock_client
                if args is None:
                    args = []
                args += '-d foo.bar -a standalone certonly'.split()
                self._call(args)

    @test_util.patch_get_utility()
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
    @test_util.patch_get_utility()
    def test_certonly_new_request_success(self, mock_get_utility, mock_notAfter):
        cert_path = '/etc/letsencrypt/live/foo.bar'
        key_path = '/etc/letsencrypt/live/baz.qux'
        date = '1970-01-01'
        mock_notAfter().date.return_value = date

        mock_lineage = mock.MagicMock(cert=cert_path, fullchain=cert_path,
                                      fullchain_path=cert_path, key_path=key_path)
        mock_client = mock.MagicMock()
        mock_client.obtain_and_enroll_certificate.return_value = mock_lineage
        self._certonly_new_request_common(mock_client)
        self.assertEqual(
            mock_client.obtain_and_enroll_certificate.call_count, 1)
        cert_msg = mock_get_utility().add_message.call_args_list[0][0][0]
        self.assertTrue(cert_path in cert_msg)
        self.assertTrue(date in cert_msg)
        self.assertTrue(key_path in cert_msg)
        self.assertTrue(
            'donate' in mock_get_utility().add_message.call_args[0][0])

    def test_certonly_new_request_failure(self):
        mock_client = mock.MagicMock()
        mock_client.obtain_and_enroll_certificate.return_value = False
        self.assertRaises(errors.Error,
                          self._certonly_new_request_common, mock_client)

    def _test_renewal_common(self, due_for_renewal, extra_args, log_out=None,
                             args=None, should_renew=True, error_expected=False,
                                 quiet_mode=False):
        # pylint: disable=too-many-locals,too-many-arguments
        cert_path = test_util.vector_path('cert_512.pem')
        chain_path = '/etc/letsencrypt/live/foo.bar/fullchain.pem'
        mock_lineage = mock.MagicMock(cert=cert_path, fullchain=chain_path,
                                      cert_path=cert_path, fullchain_path=chain_path)
        mock_lineage.should_autorenew.return_value = due_for_renewal
        mock_lineage.has_pending_deployment.return_value = False
        mock_lineage.names.return_value = ['isnot.org']
        mock_certr = mock.MagicMock()
        mock_key = mock.MagicMock(pem='pem_key')
        mock_client = mock.MagicMock()
        stdout = six.StringIO()
        mock_client.obtain_certificate.return_value = (mock_certr, 'chain',
                                                       mock_key, 'csr')

        def write_msg(message, *args, **kwargs):
            """Write message to stdout."""
            _, _ = args, kwargs
            stdout.write(message)

        try:
            with mock.patch('certbot.cert_manager.find_duplicative_certs') as mock_fdc:
                mock_fdc.return_value = (mock_lineage, None)
                with mock.patch('certbot.main._init_le_client') as mock_init:
                    mock_init.return_value = mock_client
                    with test_util.patch_get_utility() as mock_get_utility:
                        if not quiet_mode:
                            mock_get_utility().notification.side_effect = write_msg
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
                                    ret, stdout, _, _ = self._call(args, stdout)
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
                with open(os.path.join(self.config.logs_dir, "letsencrypt.log")) as lf:
                    self.assertTrue(log_out in lf.read())

        return mock_lineage, mock_get_utility, stdout

    @mock.patch('certbot.crypto_util.notAfter')
    def test_certonly_renewal(self, unused_notafter):
        lineage, get_utility, _ = self._test_renewal_common(True, [])
        self.assertEqual(lineage.save_successor.call_count, 1)
        lineage.update_all_links_to.assert_called_once_with(
            lineage.latest_common_version())
        cert_msg = get_utility().add_message.call_args_list[0][0][0]
        self.assertTrue('fullchain.pem' in cert_msg)
        self.assertTrue('donate' in get_utility().add_message.call_args[0][0])

    @mock.patch('certbot.crypto_util.notAfter')
    def test_certonly_renewal_triggers(self, unused_notafter):
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
        print("Logs:")
        log_path = os.path.join(self.config.logs_dir, "letsencrypt.log")
        if os.path.exists(log_path):
            with open(log_path) as lf:
                print(lf.read())

    def test_renew_verb(self):
        test_util.make_lineage(self.config.config_dir, 'sample-renewal.conf')
        args = ["renew", "--dry-run", "-tvv"]
        self._test_renewal_common(True, [], args=args, should_renew=True)

    def test_quiet_renew(self):
        test_util.make_lineage(self.config.config_dir, 'sample-renewal.conf')
        args = ["renew", "--dry-run"]
        _, _, stdout = self._test_renewal_common(True, [], args=args, should_renew=True)
        out = stdout.getvalue()
        self.assertTrue("renew" in out)

        args = ["renew", "--dry-run", "-q"]
        _, _, stdout = self._test_renewal_common(True, [], args=args,
                                                 should_renew=True, quiet_mode=True)
        out = stdout.getvalue()
        self.assertEqual("", out)

    def test_renew_hook_validation(self):
        test_util.make_lineage(self.config.config_dir, 'sample-renewal.conf')
        args = ["renew", "--dry-run", "--post-hook=no-such-command"]
        self._test_renewal_common(True, [], args=args, should_renew=False,
                                  error_expected=True)

    def test_renew_no_hook_validation(self):
        test_util.make_lineage(self.config.config_dir, 'sample-renewal.conf')
        args = ["renew", "--dry-run", "--post-hook=no-such-command",
                "--disable-hook-validation"]
        with mock.patch("certbot.hooks.post_hook"):
            self._test_renewal_common(True, [], args=args, should_renew=True,
                                      error_expected=False)

    def test_renew_verb_empty_config(self):
        rd = os.path.join(self.config.config_dir, 'renewal')
        if not os.path.exists(rd):
            os.makedirs(rd)
        with open(os.path.join(rd, 'empty.conf'), 'w'):
            pass  # leave the file empty
        args = ["renew", "--dry-run", "-tvv"]
        self._test_renewal_common(False, [], args=args, should_renew=False, error_expected=True)

    def test_renew_with_certname(self):
        test_util.make_lineage(self.config.config_dir, 'sample-renewal.conf')
        self._test_renewal_common(True, [], should_renew=True,
            args=['renew', '--dry-run', '--cert-name', 'sample-renewal'])

    def test_renew_with_bad_certname(self):
        self._test_renewal_common(True, [], should_renew=False,
            args=['renew', '--dry-run', '--cert-name', 'sample-renewal'],
            error_expected=True)

    def _make_dummy_renewal_config(self):
        renewer_configs_dir = os.path.join(self.config.config_dir, 'renewal')
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
            with mock.patch('certbot.main.renew_cert') as mock_renew_cert:
                kwargs.setdefault('args', ['renew'])
                self._test_renewal_common(True, None, should_renew=False, **kwargs)

            if assert_oc_called is not None:
                if assert_oc_called:
                    self.assertTrue(mock_renew_cert.called)
                else:
                    self.assertFalse(mock_renew_cert.called)

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
            with mock.patch('certbot.main.renew_cert') as mock_renew_cert:
                mock_renew_cert.side_effect = Exception
                self._test_renewal_common(True, None, error_expected=True,
                                          args=['renew'], should_renew=False)

    def test_renew_with_bad_cli_args(self):
        self._test_renewal_common(True, None, args='renew -d example.com'.split(),
                                  should_renew=False, error_expected=True)
        self._test_renewal_common(True, None, args='renew --csr {0}'.format(CSR).split(),
                                  should_renew=False, error_expected=True)

    def test_no_renewal_with_hooks(self):
        _, _, stdout = self._test_renewal_common(
            due_for_renewal=False, extra_args=None, should_renew=False,
            args=['renew', '--post-hook', 'echo hello world'])
        self.assertTrue('No hooks were run.' in stdout.getvalue())

    @test_util.patch_get_utility()
    @mock.patch('certbot.main._find_lineage_for_domains_and_certname')
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
        cert_path = '/etc/letsencrypt/live/example.com/cert_512.pem'
        full_path = '/etc/letsencrypt/live/example.com/fullchain.pem'
        mock_client.save_certificate.return_value = cert_path, None, full_path
        with mock.patch('certbot.main._init_le_client') as mock_init:
            mock_init.return_value = mock_client
            with test_util.patch_get_utility() as mock_get_utility:
                chain_path = '/etc/letsencrypt/live/example.com/chain.pem'
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
        self.assertTrue('fullchain.pem' in cert_msg)
        self.assertFalse('Your key file has been saved at' in cert_msg)
        self.assertTrue(
            'donate' in mock_get_utility().add_message.call_args[0][0])

    def test_certonly_csr_dry_run(self):
        mock_get_utility = self._test_certonly_csr_common(['--dry-run'])
        self.assertEqual(mock_get_utility().add_message.call_count, 1)
        self.assertTrue(
            'dry run' in mock_get_utility().add_message.call_args[0][0])

    @mock.patch('certbot.main._delete_if_appropriate')
    @mock.patch('certbot.main.client.acme_client')
    def test_revoke_with_key(self, mock_acme_client,
            mock_delete_if_appropriate):
        mock_delete_if_appropriate.return_value = False
        server = 'foo.bar'
        self._call_no_clientmock(['--cert-path', SS_CERT_PATH, '--key-path', RSA2048_KEY_PATH,
                                 '--server', server, 'revoke'])
        with open(RSA2048_KEY_PATH, 'rb') as f:
            mock_acme_client.Client.assert_called_once_with(
                server, key=jose.JWK.load(f.read()), net=mock.ANY)
        with open(SS_CERT_PATH, 'rb') as f:
            cert = crypto_util.pyopenssl_load_certificate(f.read())[0]
            mock_revoke = mock_acme_client.Client().revoke
            mock_revoke.assert_called_once_with(
                    jose.ComparableX509(cert),
                    mock.ANY)

    def test_revoke_with_key_mismatch(self):
        server = 'foo.bar'
        self.assertRaises(errors.Error, self._call_no_clientmock,
            ['--cert-path', CERT, '--key-path', KEY,
                                 '--server', server, 'revoke'])

    @mock.patch('certbot.main._delete_if_appropriate')
    @mock.patch('certbot.main._determine_account')
    def test_revoke_without_key(self, mock_determine_account,
            mock_delete_if_appropriate):
        mock_delete_if_appropriate.return_value = False
        mock_determine_account.return_value = (mock.MagicMock(), None)
        _, _, _, client = self._call(['--cert-path', CERT, 'revoke'])
        with open(CERT) as f:
            cert = crypto_util.pyopenssl_load_certificate(f.read())[0]
            mock_revoke = client.acme_from_config_key().revoke
            mock_revoke.assert_called_once_with(
                    jose.ComparableX509(cert),
                    mock.ANY)

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
    @test_util.patch_get_utility()
    def test_update_registration_with_email(self, mock_utility, mock_email):
        email = "user@example.com"
        mock_email.return_value = email
        with mock.patch('certbot.eff.handle_subscription') as mock_handle:
            with mock.patch('certbot.main._determine_account') as mocked_det:
                with mock.patch('certbot.main.account') as mocked_account:
                    with mock.patch('certbot.main.client') as mocked_client:
                        mocked_storage = mock.MagicMock()
                        mocked_account.AccountFileStorage.return_value = mocked_storage
                        mocked_storage.find_all.return_value = ["an account"]
                        mocked_det.return_value = (mock.MagicMock(), "foo")
                        cb_client = mock.MagicMock()
                        mocked_client.Client.return_value = cb_client
                        x = self._call_no_clientmock(
                            ["register", "--update-registration"])
                        # When registration change succeeds, the return value
                        # of register() is None
                        self.assertTrue(x[0] is None)
                        # and we got supposedly did update the registration from
                        # the server
                        self.assertTrue(
                            cb_client.acme.update_registration.called)
                        # and we saved the updated registration on disk
                        self.assertTrue(mocked_storage.save_regr.called)
                        self.assertTrue(
                            email in mock_utility().add_message.call_args[0][0])
                        self.assertTrue(mock_handle.called)


class UnregisterTest(unittest.TestCase):
    def setUp(self):
        self.patchers = {
            '_determine_account': mock.patch('certbot.main._determine_account'),
            'account': mock.patch('certbot.main.account'),
            'client': mock.patch('certbot.main.client'),
            'get_utility': test_util.patch_get_utility()}
        self.mocks = dict((k, v.start()) for k, v in self.patchers.items())

    def tearDown(self):
        for patch in self.patchers.values():
            patch.stop()

    def test_abort_unregister(self):
        self.mocks['account'].AccountFileStorage.return_value = mock.Mock()

        util_mock = self.mocks['get_utility']()
        util_mock.yesno.return_value = False

        config = mock.Mock()
        unused_plugins = mock.Mock()

        res = main.unregister(config, unused_plugins)
        self.assertEqual(res, "Deactivation aborted.")

    def test_unregister(self):
        mocked_storage = mock.MagicMock()
        mocked_storage.find_all.return_value = ["an account"]

        self.mocks['account'].AccountFileStorage.return_value = mocked_storage
        self.mocks['_determine_account'].return_value = (mock.MagicMock(), "foo")

        cb_client = mock.MagicMock()
        self.mocks['client'].Client.return_value = cb_client

        config = mock.MagicMock()
        unused_plugins = mock.MagicMock()

        res = main.unregister(config, unused_plugins)

        self.assertTrue(res is None)
        self.assertTrue(cb_client.acme.deactivate_registration.called)
        m = "Account deactivated."
        self.assertTrue(m in self.mocks['get_utility']().add_message.call_args[0][0])

    def test_unregister_no_account(self):
        mocked_storage = mock.MagicMock()
        mocked_storage.find_all.return_value = []
        self.mocks['account'].AccountFileStorage.return_value = mocked_storage

        cb_client = mock.MagicMock()
        self.mocks['client'].Client.return_value = cb_client

        config = mock.MagicMock()
        unused_plugins = mock.MagicMock()

        res = main.unregister(config, unused_plugins)
        m = "Could not find existing account to deactivate."
        self.assertEqual(res, m)
        self.assertFalse(cb_client.acme.deactivate_registration.called)


class MakeOrVerifyNeededDirs(test_util.ConfigTestCase):
    """Tests for certbot.main.make_or_verify_needed_dirs."""

    @mock.patch("certbot.main.util")
    def test_it(self, mock_util):
        main.make_or_verify_needed_dirs(self.config)
        for core_dir in (self.config.config_dir, self.config.work_dir,):
            mock_util.set_up_core_dir.assert_any_call(
                core_dir, constants.CONFIG_DIRS_MODE,
                os.geteuid(), self.config.strict_permissions
            )

        hook_dirs = (self.config.renewal_pre_hooks_dir,
                     self.config.renewal_deploy_hooks_dir,
                     self.config.renewal_post_hooks_dir,)
        for hook_dir in hook_dirs:
            # default mode of 755 is used
            mock_util.make_or_verify_dir.assert_any_call(
                hook_dir, uid=os.geteuid(),
                strict=self.config.strict_permissions)


if __name__ == '__main__':
    unittest.main()  # pragma: no cover
