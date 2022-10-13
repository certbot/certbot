# coding=utf-8
"""Tests for certbot._internal.main."""
# pylint: disable=too-many-lines
import datetime
from importlib import reload as reload_module
import io
import itertools
import json
import shutil
import sys
import tempfile
import traceback
from typing import List
import unittest

import josepy as jose
import pytz

from acme.messages import Error as acme_error
from certbot import crypto_util, configuration
from certbot import errors
from certbot import interfaces
from certbot import util
from certbot._internal import account
from certbot._internal import cli
from certbot._internal import constants
from certbot._internal import main
from certbot._internal import updater
from certbot._internal.plugins import disco
from certbot._internal.plugins import manual
from certbot._internal.plugins import null
from certbot.compat import filesystem
from certbot.compat import os
from certbot.plugins import enhancements
import certbot.tests.util as test_util

try:
    import mock
except ImportError: # pragma: no cover
    from unittest import mock



CERT_PATH = test_util.vector_path('cert_512.pem')
CERT = test_util.vector_path('cert_512.pem')
CSR = test_util.vector_path('csr_512.der')
KEY = test_util.vector_path('rsa256_key.pem')
JWK = jose.JWKRSA.load(test_util.load_vector('rsa512_key.pem'))
RSA2048_KEY_PATH = test_util.vector_path('rsa2048_key.pem')
SS_CERT_PATH = test_util.vector_path('cert_2048.pem')


class TestHandleCerts(unittest.TestCase):
    """Test for certbot._internal.main._handle_* methods"""
    @mock.patch("certbot._internal.main._handle_unexpected_key_type_migration")
    def test_handle_identical_cert_request_pending(self, mock_handle_migration):
        mock_lineage = mock.Mock()
        mock_lineage.ensure_deployed.return_value = False
        # pylint: disable=protected-access
        ret = main._handle_identical_cert_request(mock.Mock(), mock_lineage)
        self.assertEqual(ret, ("reinstall", mock_lineage))
        self.assertTrue(mock_handle_migration.called)

    @mock.patch("certbot._internal.main._handle_unexpected_key_type_migration")
    def test_handle_subset_cert_request(self, mock_handle_migration):
        mock_config = mock.Mock()
        mock_config.expand = True
        mock_lineage = mock.Mock()
        mock_lineage.names.return_value = ["dummy1", "dummy2"]
        ret = main._handle_subset_cert_request(mock_config, ["dummy1"], mock_lineage)
        self.assertEqual(ret, ("renew", mock_lineage))
        self.assertTrue(mock_handle_migration.called)

    @mock.patch("certbot._internal.main.display_util.yesno")
    @mock.patch("certbot._internal.main.cli.set_by_cli")
    def test_handle_unexpected_key_type_migration(self, mock_set, mock_yesno):
        config = mock.Mock()
        cert = mock.Mock()

        # If the key types do not differ, it should be a no-op.
        config.key_type = "rsa"
        cert.private_key_type = "rsa"
        main._handle_unexpected_key_type_migration(config, cert)
        mock_yesno.assert_not_called()
        self.assertEqual(config.key_type, cert.private_key_type)

        # If the user confirms the change interactively, the key change should proceed silently.
        cert.private_key_type = "ecdsa"
        mock_yesno.return_value = True
        main._handle_unexpected_key_type_migration(config, cert)
        self.assertEqual(mock_set.call_count, 2)
        self.assertEqual(config.key_type, "rsa")

        # User does not interactively confirm the key type change.
        mock_yesno.return_value = False

        # If --key-type and --cert-name are both set, the key type change should proceed silently.
        mock_set.return_value = True
        main._handle_unexpected_key_type_migration(config, cert)
        self.assertEqual(config.key_type, "rsa")

        # If neither --key-type nor --cert-name are set, Certbot should keep the old key type.
        mock_set.return_value = False
        main._handle_unexpected_key_type_migration(config, cert)
        self.assertEqual(config.key_type, "ecdsa")

        # If --key-type is set and --cert-name isn't, Certbot should error.
        config.key_type = "rsa"
        mock_set.side_effect = lambda var: var != "certname"
        with self.assertRaises(errors.Error) as raised:
            main._handle_unexpected_key_type_migration(config, cert)
        self.assertIn("Please provide both --cert-name and --key-type", str(raised.exception))

        # If --key-type is not set, Certbot should keep the old key type.
        mock_set.side_effect = lambda var: var != "key_type"
        main._handle_unexpected_key_type_migration(config, cert)
        self.assertEqual(config.key_type, "ecdsa")


class RunTest(test_util.ConfigTestCase):
    """Tests for certbot._internal.main.run."""

    def setUp(self):
        super().setUp()
        self.domain = 'example.org'
        patches = [
            mock.patch('certbot._internal.main._get_and_save_cert'),
            mock.patch('certbot._internal.main.display_ops.success_installation'),
            mock.patch('certbot._internal.main.display_ops.success_renewal'),
            mock.patch('certbot._internal.main._init_le_client'),
            mock.patch('certbot._internal.main._suggest_donation_if_appropriate'),
            mock.patch('certbot._internal.main._report_new_cert'),
            mock.patch('certbot._internal.main._find_cert'),
            mock.patch('certbot._internal.eff.handle_subscription'),
            mock.patch('certbot._internal.main._report_next_steps')
        ]

        self.mock_auth = patches[0].start()
        self.mock_success_installation = patches[1].start()
        self.mock_success_renewal = patches[2].start()
        self.mock_init = patches[3].start()
        self.mock_suggest_donation = patches[4].start()
        self.mock_report_cert = patches[5].start()
        self.mock_find_cert = patches[6].start()
        self.mock_subscription = patches[7].start()
        self.mock_report_next_steps = patches[8].start()
        for patch in patches:
            self.addCleanup(patch.stop)

    def _call(self):
        args = '-a webroot -i null -d {0}'.format(self.domain).split()
        plugins = disco.PluginsRegistry.find_all()
        config = configuration.NamespaceConfig(
            cli.prepare_and_parse_args(plugins, args))

        from certbot._internal.main import run
        run(config, plugins)

    def test_newcert_success(self):
        self.mock_auth.return_value = mock.Mock()
        self.mock_find_cert.return_value = True, None
        self._call()
        self.mock_success_installation.assert_called_once_with([self.domain])
        self.mock_report_next_steps.assert_called_once_with(mock.ANY, None, mock.ANY,
            new_or_renewed_cert=True)

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

    @mock.patch('certbot._internal.main.plug_sel.choose_configurator_plugins')
    def test_run_enhancement_not_supported(self, mock_choose):
        mock_choose.return_value = (null.Installer(self.config, "null"), None)
        plugins = disco.PluginsRegistry.find_all()
        self.config.auto_hsts = True
        self.assertRaises(errors.NotSupportedError,
                          main.run,
                          self.config, plugins)

    @mock.patch('certbot._internal.main._install_cert')
    def test_cert_success_install_error(self, mock_install_cert):
        mock_install_cert.side_effect = errors.PluginError("Fake installation error")
        self.mock_auth.return_value = mock.Mock()
        self.mock_find_cert.return_value = True, None
        self.assertRaises(errors.PluginError, self._call)

        # Next steps should contain both renewal advice and installation error
        self.mock_report_next_steps.assert_called_once_with(
            mock.ANY, mock_install_cert.side_effect, mock.ANY, new_or_renewed_cert=True)
        # The final success message shouldn't be shown
        self.mock_success_installation.assert_not_called()

    @mock.patch('certbot._internal.main.plug_sel.choose_configurator_plugins')
    def test_run_must_staple_not_supported(self, mock_choose):
        mock_choose.return_value = (null.Installer(self.config, "null"), None)
        plugins = disco.PluginsRegistry.find_all()
        self.config.must_staple = True
        self.assertRaises(errors.NotSupportedError,
                          main.run,
                          self.config, plugins)

class CertonlyTest(unittest.TestCase):
    """Tests for certbot._internal.main.certonly."""

    def setUp(self):
        self.get_utility_patch = test_util.patch_display_util()
        self.mock_get_utility = self.get_utility_patch.start()

    def tearDown(self):
        self.get_utility_patch.stop()

    def _call(self, args):
        plugins = disco.PluginsRegistry.find_all()
        config = configuration.NamespaceConfig(
            cli.prepare_and_parse_args(plugins, args))

        with mock.patch('certbot._internal.main._init_le_client') as mock_init:
            with mock.patch('certbot._internal.main._suggest_donation_if_appropriate'):
                with mock.patch('certbot._internal.eff.handle_subscription'):
                    main.certonly(config, plugins)

        return mock_init()  # returns the client

    @mock.patch('certbot._internal.main._find_cert')
    @mock.patch('certbot._internal.main._get_and_save_cert')
    @mock.patch('certbot._internal.main._report_new_cert')
    def test_no_reinstall_text_pause(self, unused_report, mock_auth, mock_find_cert):
        mock_notification = self.mock_get_utility().notification
        mock_notification.side_effect = self._assert_no_pause
        mock_auth.return_value = mock.Mock()
        mock_find_cert.return_value = False, None
        self._call('certonly --webroot -d example.com'.split())

    def _assert_no_pause(self, *args, **kwargs):  # pylint: disable=unused-argument
        self.assertIs(kwargs.get("pause"), False)

    @mock.patch('certbot._internal.main._report_next_steps')
    @mock.patch('certbot._internal.cert_manager.lineage_for_certname')
    @mock.patch('certbot._internal.cert_manager.domains_for_certname')
    @mock.patch('certbot._internal.renewal.renew_cert')
    @mock.patch('certbot._internal.main._handle_unexpected_key_type_migration')
    @mock.patch('certbot._internal.main._report_new_cert')
    def test_find_lineage_for_domains_and_certname(self, mock_report_cert,
        mock_handle_type, mock_renew_cert, mock_domains, mock_lineage, mock_report_next_steps):
        domains = ['example.com', 'test.org']
        mock_domains.return_value = domains
        mock_lineage.names.return_value = domains
        self._call(('certonly --webroot -d example.com -d test.org '
            '--cert-name example.com').split())

        self.assertEqual(mock_lineage.call_count, 1)
        self.assertEqual(mock_domains.call_count, 1)
        self.assertEqual(mock_renew_cert.call_count, 1)
        self.assertEqual(mock_report_cert.call_count, 1)
        self.assertEqual(mock_handle_type.call_count, 1)
        mock_report_next_steps.assert_called_once_with(
            mock.ANY, None, mock.ANY, new_or_renewed_cert=True)

        # user confirms updating lineage with new domains
        self._call(('certonly --webroot -d example.com -d test.com '
            '--cert-name example.com').split())
        self.assertEqual(mock_lineage.call_count, 2)
        self.assertEqual(mock_domains.call_count, 2)
        self.assertEqual(mock_renew_cert.call_count, 2)
        self.assertEqual(mock_report_cert.call_count, 2)
        self.assertEqual(mock_handle_type.call_count, 2)

        # error in _ask_user_to_confirm_new_names
        self.mock_get_utility().yesno.return_value = False
        self.assertRaises(errors.ConfigurationError, self._call,
            'certonly --webroot -d example.com -d test.com --cert-name example.com'.split())

    @mock.patch('certbot._internal.main._report_next_steps')
    @mock.patch('certbot._internal.cert_manager.domains_for_certname')
    @mock.patch('certbot.display.ops.choose_names')
    @mock.patch('certbot._internal.cert_manager.lineage_for_certname')
    @mock.patch('certbot._internal.main._report_new_cert')
    def test_find_lineage_for_domains_new_certname(self, mock_report_cert,
        mock_lineage, mock_choose_names, mock_domains_for_certname, unused_mock_report_next_steps):
        mock_lineage.return_value = None

        # no lineage with this name but we specified domains so create a new cert
        self._call(('certonly --webroot -d example.com -d test.com '
            '--cert-name example.com').split())
        self.assertEqual(mock_lineage.call_count, 1)
        self.assertEqual(mock_report_cert.call_count, 1)

        # no lineage with this name and we didn't give domains
        mock_choose_names.return_value = ["somename"]
        mock_domains_for_certname.return_value = None
        self._call(('certonly --webroot --cert-name example.com').split())
        self.assertIs(mock_choose_names.called, True)

    @mock.patch('certbot._internal.main._report_next_steps')
    @mock.patch('certbot._internal.main._get_and_save_cert')
    @mock.patch('certbot._internal.main._csr_get_and_save_cert')
    @mock.patch('certbot._internal.cert_manager.lineage_for_certname')
    def test_dryrun_next_steps_no_cert_saved(self, mock_lineage, mock_csr_get_cert,
                                             unused_mock_get_cert, mock_report_next_steps):
        """certonly --dry-run shouldn't report creation of a certificate in NEXT STEPS."""
        mock_lineage.return_value = None
        mock_csr_get_cert.return_value = ("/cert", "/chain", "/fullchain")
        for flag in (f"--csr {CSR}", "-d example.com"):
            self._call(f"certonly {flag} --webroot --cert-name example.com --dry-run".split())
            mock_report_next_steps.assert_called_once_with(
                mock.ANY, mock.ANY, mock.ANY, new_or_renewed_cert=False)
            mock_report_next_steps.reset_mock()

    @mock.patch('certbot._internal.main._report_next_steps')
    @mock.patch('certbot._internal.main._report_new_cert')
    @mock.patch('certbot._internal.main._find_cert')
    @mock.patch('certbot._internal.main._get_and_save_cert')
    @mock.patch('certbot._internal.plugins.selection.choose_configurator_plugins')
    def test_installer_runs_restart(self, mock_sel, mock_get_cert, mock_find_cert,
                                    unused_report_new, unused_report_next):
        mock_installer = mock.MagicMock()
        mock_sel.return_value = (mock_installer, None)
        mock_get_cert.return_value = mock.MagicMock()
        mock_find_cert.return_value = (True, None)

        self._call('certonly --nginx -d example.com'.split())
        mock_installer.restart.assert_called_once()

    @mock.patch('certbot._internal.main._report_next_steps')
    @mock.patch('certbot._internal.main._report_new_cert')
    @mock.patch('certbot._internal.main._find_cert')
    @mock.patch('certbot._internal.main._get_and_save_cert')
    @mock.patch('certbot._internal.plugins.selection.choose_configurator_plugins')
    def test_dryrun_installer_doesnt_restart(self, mock_sel, mock_get_cert, mock_find_cert,
                                             unused_report_new, unused_report_next):
        mock_installer = mock.MagicMock()
        mock_sel.return_value = (mock_installer, None)
        mock_get_cert.return_value = mock.MagicMock()
        mock_find_cert.return_value = (True, None)

        self._call('certonly --nginx -d example.com --dry-run'.split())
        mock_installer.restart.assert_not_called()


class FindDomainsOrCertnameTest(unittest.TestCase):
    """Tests for certbot._internal.main._find_domains_or_certname."""

    @mock.patch('certbot.display.ops.choose_names')
    def test_display_ops(self, mock_choose_names):
        mock_config = mock.Mock(domains=None, certname=None)
        mock_choose_names.return_value = "domainname"
        # pylint: disable=protected-access
        self.assertEqual(main._find_domains_or_certname(mock_config, None), ("domainname", None))

    @mock.patch('certbot.display.ops.choose_names')
    def test_no_results(self, mock_choose_names):
        mock_config = mock.Mock(domains=None, certname=None)
        mock_choose_names.return_value = []
        # pylint: disable=protected-access
        self.assertRaises(errors.Error, main._find_domains_or_certname, mock_config, None)

    @mock.patch('certbot._internal.cert_manager.domains_for_certname')
    def test_grab_domains(self, mock_domains):
        mock_config = mock.Mock(domains=None, certname="one.com")
        mock_domains.return_value = ["one.com", "two.com"]
        # pylint: disable=protected-access
        self.assertEqual(
            main._find_domains_or_certname(mock_config, None),
            (["one.com", "two.com"], "one.com")
        )


class RevokeTest(test_util.TempDirTestCase):
    """Tests for certbot._internal.main.revoke."""

    def setUp(self):
        super().setUp()

        shutil.copy(CERT_PATH, self.tempdir)
        self.tmp_cert_path = os.path.abspath(os.path.join(self.tempdir, 'cert_512.pem'))

        patches = [
            mock.patch('certbot._internal.client.acme_client'),
            mock.patch('certbot._internal.client.Client'),
            mock.patch('certbot._internal.main._determine_account'),
            mock.patch('certbot._internal.main.display_ops.success_revocation')
        ]
        self.mock_acme_client = patches[0].start().BackwardsCompatibleClientV2
        patches[1].start()
        self.mock_determine_account = patches[2].start()
        self.mock_success_revoke = patches[3].start()
        for patch in patches:
            self.addCleanup(patch.stop)

        from certbot._internal.account import Account

        self.regr = mock.MagicMock()
        self.meta = Account.Meta(
            creation_host="test.certbot.org",
            creation_dt=datetime.datetime(
                2015, 7, 4, 14, 4, 10, tzinfo=pytz.UTC))
        self.acc = Account(self.regr, JWK, self.meta)

        self.mock_determine_account.return_value = (self.acc, None)

    def _call(self, args=None):
        if not args:
            args = 'revoke --cert-path={0} '
            args = args.format(self.tmp_cert_path).split()
        cli.set_by_cli.detector = None # required to reset set_by_cli state
        plugins = disco.PluginsRegistry.find_all()
        config = configuration.NamespaceConfig(
            cli.prepare_and_parse_args(plugins, args))

        from certbot._internal.main import revoke
        revoke(config, plugins)

    @mock.patch('certbot._internal.main._delete_if_appropriate')
    @mock.patch('certbot._internal.main.client.acme_client')
    def test_revoke_with_reason(self, mock_acme_client,
            mock_delete_if_appropriate):
        mock_delete_if_appropriate.return_value = False
        mock_revoke = mock_acme_client.BackwardsCompatibleClientV2().revoke
        expected = []
        for reason, code in constants.REVOCATION_REASONS.items():
            args = 'revoke --cert-path={0} --reason {1}'.format(self.tmp_cert_path, reason).split()
            self._call(args)
            expected.append(mock.call(mock.ANY, code))
            args = 'revoke --cert-path={0} --reason {1}'.format(self.tmp_cert_path,
                    reason.upper()).split()
            self._call(args)
            expected.append(mock.call(mock.ANY, code))
        self.assertEqual(expected, mock_revoke.call_args_list)

    @mock.patch('certbot._internal.main._delete_if_appropriate')
    @mock.patch('certbot._internal.storage.RenewableCert')
    @mock.patch('certbot._internal.storage.renewal_file_for_certname')
    def test_revoke_by_certname(self, unused_mock_renewal_file_for_certname,
                                mock_cert, mock_delete_if_appropriate):
        mock_cert.return_value = mock.MagicMock(cert_path=self.tmp_cert_path,
                                                server="https://acme.example")
        args = 'revoke --cert-name=example.com'.split()
        mock_delete_if_appropriate.return_value = False
        self._call(args)
        self.mock_acme_client.assert_called_once_with(mock.ANY, mock.ANY, 'https://acme.example')
        self.mock_success_revoke.assert_called_once_with(self.tmp_cert_path)

    @mock.patch('certbot._internal.main._delete_if_appropriate')
    @mock.patch('certbot._internal.storage.RenewableCert')
    @mock.patch('certbot._internal.storage.renewal_file_for_certname')
    def test_revoke_by_certname_and_server(self, unused_mock_renewal_file_for_certname,
                                           mock_cert, mock_delete_if_appropriate):
        """Revoking with --server should use the server from the CLI"""
        mock_cert.return_value = mock.MagicMock(cert_path=self.tmp_cert_path,
                                                server="https://acme.example")
        args = 'revoke --cert-name=example.com --server https://other.example'.split()
        mock_delete_if_appropriate.return_value = False
        self._call(args)
        self.mock_acme_client.assert_called_once_with(mock.ANY, mock.ANY, 'https://other.example')
        self.mock_success_revoke.assert_called_once_with(self.tmp_cert_path)

    @mock.patch('certbot._internal.main._delete_if_appropriate')
    @mock.patch('certbot._internal.storage.RenewableCert')
    @mock.patch('certbot._internal.storage.renewal_file_for_certname')
    def test_revoke_by_certname_empty_server(self, unused_mock_renewal_file_for_certname,
                                             mock_cert, mock_delete_if_appropriate):
        """Revoking with --cert-name where the lineage server is empty shouldn't crash """
        mock_cert.return_value = mock.MagicMock(cert_path=self.tmp_cert_path, server=None)
        args = 'revoke --cert-name=example.com'.split()
        mock_delete_if_appropriate.return_value = False
        self._call(args)
        self.mock_acme_client.assert_called_once_with(
            mock.ANY, mock.ANY, constants.CLI_DEFAULTS['server'])
        self.mock_success_revoke.assert_called_once_with(self.tmp_cert_path)

    @mock.patch('certbot._internal.main._delete_if_appropriate')
    def test_revocation_success(self, mock_delete_if_appropriate):
        self._call()
        mock_delete_if_appropriate.return_value = False
        self.mock_success_revoke.assert_called_once_with(self.tmp_cert_path)

    def test_revocation_error(self):
        from acme import errors as acme_errors
        self.mock_acme_client.side_effect = acme_errors.ClientError()
        self.assertRaises(acme_errors.ClientError, self._call)
        self.mock_success_revoke.assert_not_called()

    @mock.patch('certbot._internal.main._delete_if_appropriate')
    @mock.patch('certbot._internal.cert_manager.delete')
    @test_util.patch_display_util()
    def test_revocation_with_prompt(self, mock_get_utility,
            mock_delete, mock_delete_if_appropriate):
        mock_get_utility().yesno.return_value = False
        mock_delete_if_appropriate.return_value = False
        self._call()
        self.assertIs(mock_delete.called, False)


# class CertonlyTest(unittest.TestCase):
#     """Tests for certbot._internal.main.certonly."""

#     def setUp(self):
#         self.get_utility_patch = test_util.patch_display_util()
#         self.mock_get_utility = self.get_utility_patch.start()

#     def tearDown(self):
#         self.get_utility_patch.stop()



class ReconfigureTest(unittest.TestCase):
    """Tests for certbot._internal.main.reconfigure"""

    def setUp(self):
        self.get_utility_patch = test_util.patch_display_util()
        self.mock_get_utility = self.get_utility_patch.start()

    def tearDown(self):
        self.get_utility_patch.stop()

    def _call(self, args):
        plugins = disco.PluginsRegistry.find_all()
        config = configuration.NamespaceConfig(
            cli.prepare_and_parse_args(plugins, args))

        from certbot._internal.main import reconfigure
        with mock.patch('certbot._internal.main._init_le_client') as mock_init:
            reconfigure(config, plugins)

        return mock_init() # returns the client for some reason

    def test_domains_set(self):
        self.assertRaises(errors.ConfigurationError,
            self._call, '--cert-name cert1 -d one.cert.com')

    def test_asks_for_certname(self):
        self._call('--nginx')
        pass
        # self._call('reconfigure --cert-name cert1')

    def test_update_auth(self):
        pass
        # self._call()

    def test_update_hook(self):
        pass

    def test_no_domains(self):
        pass



class DeleteIfAppropriateTest(test_util.ConfigTestCase):
    """Tests for certbot._internal.main._delete_if_appropriate """

    def _call(self, mock_config):
        from certbot._internal.main import _delete_if_appropriate
        _delete_if_appropriate(mock_config)

    def _test_delete_opt_out_common(self):
        with mock.patch('certbot._internal.cert_manager.delete') as mock_delete:
            self._call(self.config)
        mock_delete.assert_not_called()

    @test_util.patch_display_util()
    def test_delete_flag_opt_out(self, unused_mock_get_utility):
        self.config.delete_after_revoke = False
        self._test_delete_opt_out_common()

    @test_util.patch_display_util()
    def test_delete_prompt_opt_out(self, mock_get_utility):
        util_mock = mock_get_utility()
        util_mock.yesno.return_value = False
        self._test_delete_opt_out_common()

    @mock.patch("certbot._internal.main.logger.warning")
    @mock.patch('certbot._internal.storage.renewal_file_for_certname')
    @mock.patch('certbot._internal.cert_manager.delete')
    @mock.patch('certbot._internal.cert_manager.match_and_check_overlaps')
    @mock.patch('certbot._internal.storage.full_archive_path')
    @mock.patch('certbot._internal.cert_manager.cert_path_to_lineage')
    @test_util.patch_display_util()
    def test_overlapping_archive_dirs(self, mock_get_utility,
            mock_cert_path_to_lineage, mock_archive,
            mock_match_and_check_overlaps, mock_delete,
            mock_renewal_file_for_certname, mock_warning):
        # pylint: disable = unused-argument
        config = self.config
        config.cert_path = "/some/reasonable/path"
        config.certname = ""
        mock_cert_path_to_lineage.return_value = "example.com"
        mock_match_and_check_overlaps.side_effect = errors.OverlappingMatchFound()
        self._call(config)
        mock_delete.assert_not_called()
        self.assertEqual(mock_warning.call_count, 1)

    @mock.patch('certbot._internal.storage.renewal_file_for_certname')
    @mock.patch('certbot._internal.cert_manager.match_and_check_overlaps')
    @mock.patch('certbot._internal.storage.full_archive_path')
    @mock.patch('certbot._internal.cert_manager.delete')
    @mock.patch('certbot._internal.cert_manager.cert_path_to_lineage')
    @test_util.patch_display_util()
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
        self.assertEqual(mock_delete.call_count, 1)

    @mock.patch('certbot._internal.storage.renewal_file_for_certname')
    @mock.patch('certbot._internal.cert_manager.match_and_check_overlaps')
    @mock.patch('certbot._internal.storage.full_archive_path')
    @mock.patch('certbot._internal.cert_manager.cert_path_to_lineage')
    @mock.patch('certbot._internal.cert_manager.delete')
    @test_util.patch_display_util()
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
        self.assertEqual(mock_delete.call_count, 1)

    @mock.patch('certbot._internal.storage.renewal_file_for_certname')
    @mock.patch('certbot._internal.cert_manager.match_and_check_overlaps')
    @mock.patch('certbot._internal.storage.full_archive_path')
    @mock.patch('certbot._internal.cert_manager.cert_path_to_lineage')
    @mock.patch('certbot._internal.cert_manager.delete')
    @test_util.patch_display_util()
    def test_opt_in_deletion(self, mock_get_utility, mock_delete,
            mock_cert_path_to_lineage, mock_full_archive_dir,
            mock_match_and_check_overlaps, mock_renewal_file_for_certname):
        config = self.config
        config.namespace.delete_after_revoke = True
        config.cert_path = "/some/reasonable/path"
        config.certname = ""
        mock_cert_path_to_lineage.return_value = "example.com"
        mock_full_archive_dir.return_value = ""
        mock_match_and_check_overlaps.return_value = ""
        self._call(config)
        self.assertEqual(mock_delete.call_count, 1)
        self.assertFalse(mock_get_utility().yesno.called)


class DetermineAccountTest(test_util.ConfigTestCase):
    """Tests for certbot._internal.main._determine_account."""

    def setUp(self):
        super().setUp()
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
        from certbot._internal.main import _determine_account
        with mock.patch('certbot._internal.main.account.AccountFileStorage') as mock_storage, \
             test_util.patch_display_util():
            mock_storage.return_value = self.account_storage
            return _determine_account(self.config)

    @mock.patch('certbot._internal.client.register')
    @mock.patch('certbot._internal.client.display_ops.get_email')
    def _register_error_common(self, err_msg, exception, mock_get_email, mock_register):
        mock_get_email.return_value = 'foo@bar.baz'
        mock_register.side_effect = exception
        try:
            self._call()
        except errors.Error as err:
            self.assertEqual(f"Unable to register an account with ACME server. {err_msg}",
                             str(err))

    def test_args_account_set(self):
        self.account_storage.save(self.accs[1], self.mock_client)
        self.config.account = self.accs[1].id
        self.assertEqual((self.accs[1], None), self._call())
        self.assertEqual(self.accs[1].id, self.config.account)
        self.assertIsNone(self.config.email)

    def test_single_account(self):
        self.account_storage.save(self.accs[0], self.mock_client)
        self.assertEqual((self.accs[0], None), self._call())
        self.assertEqual(self.accs[0].id, self.config.account)
        self.assertIsNone(self.config.email)

    @mock.patch('certbot._internal.client.display_ops.choose_account')
    def test_multiple_accounts(self, mock_choose_accounts):
        for acc in self.accs:
            self.account_storage.save(acc, self.mock_client)
        mock_choose_accounts.return_value = self.accs[1]
        self.assertEqual((self.accs[1], None), self._call())
        self.assertEqual(
            set(mock_choose_accounts.call_args[0][0]), set(self.accs))
        self.assertEqual(self.accs[1].id, self.config.account)
        self.assertIsNone(self.config.email)

    @mock.patch('certbot._internal.client.display_ops.choose_account')
    def test_multiple_accounts_canceled(self, mock_choose_accounts):
        for acc in self.accs:
            self.account_storage.save(acc, self.mock_client)
        mock_choose_accounts.return_value = None
        try:
            self._call()
        except errors.Error as err:
            self.assertIn("No account has been chosen", str(err))

    @mock.patch('certbot._internal.client.display_ops.get_email')
    @mock.patch('certbot._internal.main.display_util.notify')
    def test_no_accounts_no_email(self, mock_notify, mock_get_email):
        mock_get_email.return_value = 'foo@bar.baz'

        with mock.patch('certbot._internal.main.client') as client:
            client.register.return_value = (
                self.accs[0], mock.sentinel.acme)
            self.assertEqual((self.accs[0], mock.sentinel.acme), self._call())
        client.register.assert_called_once_with(
            self.config, self.account_storage, tos_cb=mock.ANY)

        self.assertEqual(self.accs[0].id, self.config.account)
        self.assertEqual('foo@bar.baz', self.config.email)
        mock_notify.assert_called_once_with('Account registered.')

    def test_no_accounts_email(self):
        self.config.email = 'other email'
        with mock.patch('certbot._internal.main.client') as client:
            client.register.return_value = (self.accs[1], mock.sentinel.acme)
            self._call()
        self.assertEqual(self.accs[1].id, self.config.account)
        self.assertEqual('other email', self.config.email)

    def test_register_error_certbot(self):
        err_msg = "Some error message raised by Certbot"
        self._register_error_common(err_msg, errors.Error(err_msg))

    def test_register_error_acme_type_and_detail(self):
        err_msg = ("Error returned by the ACME server: must agree to terms of service")
        exception = acme_error(typ = "urn:ietf:params:acme:error:malformed",
                               detail = "must agree to terms of service")
        self._register_error_common(err_msg, exception)

    def test_register_error_acme_type_only(self):
        err_msg = ("Error returned by the ACME server: The server experienced an internal error")
        exception = acme_error(typ = "urn:ietf:params:acme:error:serverInternal")
        self._register_error_common(err_msg, exception)


class MainTest(test_util.ConfigTestCase):
    """Tests for different commands."""

    def setUp(self):
        super().setUp()

        filesystem.mkdir(self.config.logs_dir)
        self.standard_args = ['--config-dir', self.config.config_dir,
                              '--work-dir', self.config.work_dir,
                              '--logs-dir', self.config.logs_dir, '--text']

        self.mock_sleep = mock.patch('time.sleep').start()

    def tearDown(self):
        # Reset globals in cli
        reload_module(cli)

        super().tearDown()

    def _call(self, args, stdout=None, mockisfile=False):
        """Run the cli with output streams, actual client and optionally
        os.path.isfile() mocked out"""

        if mockisfile:
            orig_open = os.path.isfile

            def mock_isfile(fn, *args, **kwargs):  # pylint: disable=unused-argument
                """Mock os.path.isfile()"""
                if (fn.endswith("cert") or
                        fn.endswith("chain") or
                        fn.endswith("privkey")):
                    return True
                return orig_open(fn)

            with mock.patch("certbot.compat.os.path.isfile") as mock_if:
                mock_if.side_effect = mock_isfile
                with mock.patch('certbot._internal.main.client') as client:
                    ret, stdout, stderr = self._call_no_clientmock(args, stdout)
                    return ret, stdout, stderr, client
        else:
            with mock.patch('certbot._internal.main.client') as client:
                ret, stdout, stderr = self._call_no_clientmock(args, stdout)
                return ret, stdout, stderr, client

    def _call_no_clientmock(self, args, stdout=None):
        """Run the client with output streams mocked out"""
        args = self.standard_args + args

        toy_stdout = stdout if stdout else io.StringIO()
        with mock.patch('certbot._internal.main.sys.stdout', new=toy_stdout):
            with mock.patch('certbot._internal.main.sys.stderr') as stderr:
                with mock.patch("certbot.util.atexit"):
                    ret = main.main(args[:])  # NOTE: parser can alter its args!
        return ret, toy_stdout, stderr

    def test_no_flags(self):
        with mock.patch('certbot._internal.main.run') as mock_run:
            self._call([])
            self.assertEqual(1, mock_run.call_count)

    def test_version_string_program_name(self):
        toy_out = io.StringIO()
        toy_err = io.StringIO()
        with mock.patch('certbot._internal.main.sys.stdout', new=toy_out):
            with mock.patch('certbot._internal.main.sys.stderr', new=toy_err):
                try:
                    main.main(["--version"])
                except SystemExit:
                    pass
                finally:
                    output = toy_out.getvalue() or toy_err.getvalue()
                    self.assertIn("certbot", output, "Output is {0}".format(output))

    def _cli_missing_flag(self, args, message):
        "Ensure that a particular error raises a missing cli flag error containing message"
        exc = None
        try:
            with mock.patch('certbot._internal.main.sys.stderr'):
                main.main(self.standard_args + args[:])  # NOTE: parser can alter its args!
        except errors.MissingCommandlineFlag as exc_:
            exc = exc_
            self.assertIn(message, str(exc))
        self.assertIsNotNone(exc)

    @mock.patch('certbot._internal.log.post_arg_parse_setup')
    def test_noninteractive(self, _):
        args = ['-n', 'certonly']
        self._cli_missing_flag(args, "specify a plugin")
        args.extend(['--standalone', '-d', 'eg.is'])
        self._cli_missing_flag(args, "register before running")

    @mock.patch('certbot._internal.eff.handle_subscription')
    @mock.patch('certbot._internal.log.post_arg_parse_setup')
    @mock.patch('certbot._internal.main._report_new_cert')
    @mock.patch('certbot._internal.main._determine_account')
    @mock.patch('certbot._internal.main.client.Client.obtain_and_enroll_certificate')
    @mock.patch('certbot._internal.main._get_and_save_cert')
    def test_user_agent(self, gsc, _obt, det, _, __, ___):
        # Normally the client is totally mocked out, but here we need more
        # arguments to automate it...
        args = ["--standalone", "certonly", "-m", "none@none.com",
                "-d", "example.com", '--agree-tos'] + self.standard_args
        det.return_value = mock.MagicMock(), None
        gsc.return_value = mock.MagicMock()

        with mock.patch('certbot._internal.main.client.acme_client') as acme_client:
            acme_net = acme_client.ClientNetwork
            self._call_no_clientmock(args)
            os_ver = util.get_os_info_ua()
            ua = acme_net.call_args[1]["user_agent"]
            self.assertIn(os_ver, ua)
            import platform
            plat = platform.platform()
            if "linux" in plat.lower():
                self.assertIn(util.get_os_info_ua(), ua)

        with mock.patch('certbot._internal.main.client.acme_client') as acme_client:
            acme_net = acme_client.ClientNetwork
            ua = "bandersnatch"
            args += ["--user-agent", ua]
            self._call_no_clientmock(args)
            acme_net.assert_called_once_with(mock.ANY, account=mock.ANY, verify_ssl=True,
                user_agent=ua, alg=jose.RS256)

    @mock.patch('certbot._internal.main.plug_sel.record_chosen_plugins')
    @mock.patch('certbot._internal.main.plug_sel.pick_installer')
    def test_installer_selection(self, mock_pick_installer, _rec):
        self._call(['install', '--domains', 'foo.bar', '--cert-path', 'cert',
                    '--key-path', 'privkey', '--chain-path', 'chain'], mockisfile=True)
        self.assertEqual(mock_pick_installer.call_count, 1)

    @mock.patch('certbot._internal.main._install_cert')
    @mock.patch('certbot._internal.main.plug_sel.record_chosen_plugins')
    @mock.patch('certbot._internal.main.plug_sel.pick_installer')
    def test_installer_certname(self, _inst, _rec, mock_install):
        mock_lineage = mock.MagicMock(cert_path=test_util.temp_join('cert'),
                                      chain_path=test_util.temp_join('chain'),
                                      fullchain_path=test_util.temp_join('chain'),
                                      key_path=test_util.temp_join('privkey'))

        with mock.patch("certbot._internal.cert_manager.lineage_for_certname") as mock_getlin:
            mock_getlin.return_value = mock_lineage
            self._call(['install', '--cert-name', 'whatever'], mockisfile=True)
            call_config = mock_install.call_args[0][0]
            self.assertEqual(call_config.cert_path, test_util.temp_join('cert'))
            self.assertEqual(call_config.fullchain_path, test_util.temp_join('chain'))
            self.assertEqual(call_config.key_path, test_util.temp_join('privkey'))

    @mock.patch('certbot._internal.log.post_arg_parse_setup')
    @mock.patch('certbot._internal.main._install_cert')
    @mock.patch('certbot._internal.main.plug_sel.record_chosen_plugins')
    @mock.patch('certbot._internal.main.plug_sel.pick_installer')
    def test_installer_param_override(self, _inst, _rec, mock_install, _):
        mock_lineage = mock.MagicMock(cert_path=test_util.temp_join('cert'),
                                      chain_path=test_util.temp_join('chain'),
                                      fullchain_path=test_util.temp_join('chain'),
                                      key_path=test_util.temp_join('privkey'))
        with mock.patch("certbot._internal.cert_manager.lineage_for_certname") as mock_getlin:
            mock_getlin.return_value = mock_lineage
            self._call(['install', '--cert-name', 'whatever',
                        '--key-path', test_util.temp_join('overriding_privkey')], mockisfile=True)
            call_config = mock_install.call_args[0][0]
            self.assertEqual(call_config.cert_path, test_util.temp_join('cert'))
            self.assertEqual(call_config.fullchain_path, test_util.temp_join('chain'))
            self.assertEqual(call_config.chain_path, test_util.temp_join('chain'))
            self.assertEqual(call_config.key_path, test_util.temp_join('overriding_privkey'))

            mock_install.reset()

            self._call(['install', '--cert-name', 'whatever',
                        '--cert-path', test_util.temp_join('overriding_cert')], mockisfile=True)
            call_config = mock_install.call_args[0][0]
            self.assertEqual(call_config.cert_path, test_util.temp_join('overriding_cert'))
            self.assertEqual(call_config.fullchain_path, test_util.temp_join('chain'))
            self.assertEqual(call_config.key_path, test_util.temp_join('privkey'))

    @mock.patch('certbot._internal.main.plug_sel.record_chosen_plugins')
    @mock.patch('certbot._internal.main.plug_sel.pick_installer')
    def test_installer_param_error(self, _inst, _rec):
        self.assertRaises(errors.ConfigurationError,
                          self._call,
                          ['install', '--cert-name', 'notfound',
                           '--key-path', 'invalid'])

    @mock.patch('certbot._internal.main.plug_sel.record_chosen_plugins')
    @mock.patch('certbot._internal.main.plug_sel.pick_installer')
    @mock.patch('certbot._internal.cert_manager.get_certnames')
    @mock.patch('certbot._internal.main._install_cert')
    def test_installer_select_cert(self, mock_inst, mock_getcert, _inst, _rec):
        mock_lineage = mock.MagicMock(cert_path=test_util.temp_join('cert'),
                                      chain_path=test_util.temp_join('chain'),
                                      fullchain_path=test_util.temp_join('chain'),
                                      key_path=test_util.temp_join('privkey'))
        with mock.patch("certbot._internal.cert_manager.lineage_for_certname") as mock_getlin:
            mock_getlin.return_value = mock_lineage
            self._call(['install'], mockisfile=True)
        self.assertTrue(mock_getcert.called)
        self.assertTrue(mock_inst.called)

    @mock.patch('certbot._internal.eff.handle_subscription')
    @mock.patch('certbot._internal.log.post_arg_parse_setup')
    @mock.patch('certbot._internal.main._report_new_cert')
    @mock.patch('certbot.util.exe_exists')
    def test_configurator_selection(self, mock_exe_exists, _, __, ___):
        mock_exe_exists.return_value = True
        real_plugins = disco.PluginsRegistry.find_all()
        args = ['--apache', '--authenticator', 'standalone']

        # This needed two calls to find_all(), which we're avoiding for now
        # because of possible side effects:
        # https://github.com/letsencrypt/letsencrypt/commit/51ed2b681f87b1eb29088dd48718a54f401e4855
        # with mock.patch('certbot._internal.cli.plugins_testable') as plugins:
        #    plugins.return_value = {"apache": True, "nginx": True}
        #    ret, _, _, _ = self._call(args)
        #    self.assertTrue("Too many flags setting" in ret)

        args = ["install", "--nginx", "--cert-path",
                test_util.temp_join('blah'), "--key-path", test_util.temp_join('blah'),
                "--nginx-server-root", "/nonexistent/thing", "-d",
                "example.com", "--debug"]
        if "nginx" in real_plugins:
            # Sending nginx a non-existent conf dir will simulate misconfiguration
            # (we can only do that if certbot-nginx is actually present)
            ret, _, _, _ = self._call(args)
            self.assertIn("The nginx plugin is not working", ret)
            self.assertIn("MisconfigurationError", ret)

        self._cli_missing_flag(["--standalone"], "With the standalone plugin, you probably")

        with mock.patch("certbot._internal.main._init_le_client") as mock_init:
            with mock.patch("certbot._internal.main._get_and_save_cert") as mock_gsc:
                mock_gsc.return_value = mock.MagicMock()
                self._call(["certonly", "--manual", "-d", "foo.bar"])
                unused_config, auth, unused_installer = mock_init.call_args[0]
                self.assertIsInstance(auth, manual.Authenticator)

        with mock.patch('certbot._internal.main.certonly') as mock_certonly:
            self._call(["auth", "--standalone"])
            self.assertEqual(1, mock_certonly.call_count)

    @mock.patch('certbot._internal.log.post_arg_parse_setup')
    def test_rollback(self, _):
        _, _, _, client = self._call(['rollback'])
        self.assertEqual(1, client.rollback.call_count)

        _, _, _, client = self._call(['rollback', '--checkpoints', '123'])
        client.rollback.assert_called_once_with(
            mock.ANY, 123, mock.ANY, mock.ANY)

    @mock.patch('certbot._internal.cert_manager.update_live_symlinks')
    def test_update_symlinks(self, mock_cert_manager):
        self._call_no_clientmock(['update_symlinks'])
        self.assertEqual(1, mock_cert_manager.call_count)

    @mock.patch('certbot._internal.cert_manager.certificates')
    def test_certificates(self, mock_cert_manager):
        self._call_no_clientmock(['certificates'])
        self.assertEqual(1, mock_cert_manager.call_count)

    @mock.patch('certbot._internal.cert_manager.delete')
    def test_delete(self, mock_cert_manager):
        self._call_no_clientmock(['delete'])
        self.assertEqual(1, mock_cert_manager.call_count)

    @mock.patch('certbot._internal.main.plugins_disco')
    @mock.patch('certbot._internal.main.cli.HelpfulArgumentParser.determine_help_topics')
    @mock.patch('certbot._internal.log.post_arg_parse_setup')
    def test_plugins(self, _, _det, mock_disco):
        flags = ['--init', '--prepare', '--authenticators', '--installers']
        for args in itertools.chain(
                *(itertools.combinations(flags, r)
                  for r in range(len(flags)))):
            self._call(['plugins'] + list(args))

    @mock.patch('certbot._internal.main.plugins_disco')
    @mock.patch('certbot._internal.main.cli.HelpfulArgumentParser.determine_help_topics')
    def test_plugins_no_args(self, _det, mock_disco):
        ifaces: List[interfaces.Plugin] = []
        plugins = mock_disco.PluginsRegistry.find_all()

        stdout = io.StringIO()
        with test_util.patch_display_util_with_stdout(stdout=stdout):
            _, stdout, _, _ = self._call(['plugins'], stdout)

        plugins.visible.assert_called_once_with()
        plugins.visible().ifaces.assert_called_once_with(ifaces)
        filtered = plugins.visible().ifaces()
        self.assertEqual(stdout.getvalue().strip(), str(filtered))

    @mock.patch('certbot._internal.main.plugins_disco')
    @mock.patch('certbot._internal.main.cli.HelpfulArgumentParser.determine_help_topics')
    def test_plugins_no_args_unprivileged(self, _det, mock_disco):
        ifaces: List[interfaces.Plugin] = []
        plugins = mock_disco.PluginsRegistry.find_all()

        def throw_error(directory, mode, strict):
            """Raises error.Error."""
            _, _, _ = directory, mode, strict
            raise errors.Error()

        stdout = io.StringIO()
        with mock.patch('certbot.util.set_up_core_dir') as mock_set_up_core_dir:
            with test_util.patch_display_util_with_stdout(stdout=stdout):
                mock_set_up_core_dir.side_effect = throw_error
                _, stdout, _, _ = self._call(['plugins'], stdout)

        plugins.visible.assert_called_once_with()
        plugins.visible().ifaces.assert_called_once_with(ifaces)
        filtered = plugins.visible().ifaces()
        self.assertEqual(stdout.getvalue().strip(), str(filtered))

    @mock.patch('certbot._internal.main.plugins_disco')
    @mock.patch('certbot._internal.main.cli.HelpfulArgumentParser.determine_help_topics')
    def test_plugins_init(self, _det, mock_disco):
        ifaces: List[interfaces.Plugin] = []
        plugins = mock_disco.PluginsRegistry.find_all()

        stdout = io.StringIO()
        with test_util.patch_display_util_with_stdout(stdout=stdout):
            _, stdout, _, _ = self._call(['plugins', '--init'], stdout)

        plugins.visible.assert_called_once_with()
        plugins.visible().ifaces.assert_called_once_with(ifaces)
        filtered = plugins.visible().ifaces()
        self.assertEqual(filtered.init.call_count, 1)
        filtered.verify.assert_called_once_with(ifaces)
        verified = filtered.verify()
        self.assertEqual(stdout.getvalue().strip(), str(verified))

    @mock.patch('certbot._internal.main.plugins_disco')
    @mock.patch('certbot._internal.main.cli.HelpfulArgumentParser.determine_help_topics')
    def test_plugins_prepare(self, _det, mock_disco):
        ifaces: List[interfaces.Plugin] = []
        plugins = mock_disco.PluginsRegistry.find_all()

        stdout = io.StringIO()
        with test_util.patch_display_util_with_stdout(stdout=stdout):
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

        with mock.patch('certbot._internal.main.certonly') as mock_certonly:
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
            self.assertIn('The requested bad_auth plugin does not appear', str(e))

    def test_check_config_sanity_domain(self):
        # FQDN
        self.assertRaises(errors.ConfigurationError,
                          self._call,
                          ['-d', 'a' * 64])
        # FQDN 2
        self.assertRaises(errors.ConfigurationError,
                          self._call,
                          ['-d', (('a' * 50) + '.') * 10])
        # Bare IP address (this is actually a different error message now)
        self.assertRaises(errors.ConfigurationError,
                          self._call,
                          ['-d', '204.11.231.35'])
        # Bare IPv6 address
        self.assertRaises(errors.ConfigurationError,
                          self._call,
                          ['-d', '2001:db8:ac69:3ff:b1cb:c8c6:5a84:a31b'])

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
        with mock.patch('certbot._internal.main._find_lineage_for_domains_and_certname') \
            as mock_renewal:
            mock_renewal.return_value = ("newcert", None)
            with mock.patch('certbot._internal.main._init_le_client') as mock_init:
                mock_init.return_value = mock_client
                if args is None:
                    args = []
                args += '-d foo.bar -a standalone certonly'.split()
                self._call(args)

    @mock.patch('certbot._internal.main._report_new_cert')
    def test_certonly_dry_run_new_request_success(self, mock_report):
        mock_client = mock.MagicMock()
        mock_client.obtain_and_enroll_certificate.return_value = None
        self._certonly_new_request_common(mock_client, ['--dry-run'])
        self.assertEqual(
            mock_client.obtain_and_enroll_certificate.call_count, 1)
        self.assertEqual(mock_report.call_count, 1)
        self.assertIs(mock_report.call_args[0][0].dry_run, True)

    @mock.patch('certbot._internal.main._report_new_cert')
    @mock.patch('certbot._internal.main.util.atexit_register')
    @mock.patch('certbot._internal.eff.handle_subscription')
    @mock.patch('certbot.crypto_util.notAfter')
    def test_certonly_new_request_success(self, mock_notAfter,
                                          mock_subscription, mock_register, mock_report):
        cert_path = os.path.normpath(os.path.join(self.config.config_dir, 'live/foo.bar'))
        key_path = os.path.normpath(os.path.join(self.config.config_dir, 'live/baz.qux'))
        date = '1970-01-01'
        mock_notAfter().date.return_value = date

        mock_lineage = mock.MagicMock(cert=cert_path, fullchain=cert_path,
                                      fullchain_path=cert_path, key_path=key_path)
        mock_client = mock.MagicMock()
        mock_client.obtain_and_enroll_certificate.return_value = mock_lineage
        self._certonly_new_request_common(mock_client)
        self.assertEqual(
            mock_client.obtain_and_enroll_certificate.call_count, 1)
        self.assertEqual(mock_report.call_count, 1)
        self.assertIn(cert_path, mock_report.call_args[0][2])
        self.assertIn(key_path, mock_report.call_args[0][3])
        self.assertIn('donate',  mock_register.call_args[0][1])
        self.assertIs(mock_subscription.called, True)

    @mock.patch('certbot._internal.eff.handle_subscription')
    def test_certonly_new_request_failure(self, mock_subscription):
        mock_client = mock.MagicMock()
        mock_client.obtain_and_enroll_certificate.return_value = False
        self.assertRaises(errors.Error,
                          self._certonly_new_request_common, mock_client)
        self.assertIs(mock_subscription.called, False)

    def _test_renewal_common(self, due_for_renewal, extra_args, log_out=None,
                             args=None, should_renew=True, error_expected=False,
                             quiet_mode=False, expiry_date=datetime.datetime.now(),
                             reuse_key=False, new_key=False):
        cert_path = test_util.vector_path('cert_512.pem')
        chain_path = os.path.normpath(os.path.join(self.config.config_dir,
                                                   'live/foo.bar/fullchain.pem'))
        mock_lineage = mock.MagicMock(cert=cert_path, fullchain=chain_path,
                                      cert_path=cert_path, fullchain_path=chain_path)
        mock_lineage.should_autorenew.return_value = due_for_renewal
        mock_lineage.has_pending_deployment.return_value = False
        mock_lineage.names.return_value = ['isnot.org']
        mock_lineage.private_key_type = 'RSA'
        mock_certr = mock.MagicMock()
        mock_key = mock.MagicMock(pem='pem_key')
        mock_client = mock.MagicMock()
        stdout = io.StringIO()
        mock_client.obtain_certificate.return_value = (mock_certr, 'chain',
                                                       mock_key, 'csr')

        def write_msg(message, *args, **kwargs):  # pylint: disable=unused-argument
            """Write message to stdout."""
            stdout.write(message)

        try:
            with mock.patch('certbot._internal.cert_manager.find_duplicative_certs') as mock_fdc:
                mock_fdc.return_value = (mock_lineage, None)
                with mock.patch('certbot._internal.main._init_le_client') as mock_init:
                    mock_init.return_value = mock_client
                    with mock.patch('certbot._internal.display.obj.get_display') as mock_display:
                        if not quiet_mode:
                            mock_display().notification.side_effect = write_msg
                        with mock.patch('certbot._internal.main.renewal.crypto_util') \
                            as mock_crypto_util:
                            mock_crypto_util.notAfter.return_value = expiry_date
                            with mock.patch('certbot._internal.eff.handle_subscription'):
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
                if reuse_key and not new_key:
                    # The location of the previous live privkey.pem is passed
                    # to obtain_certificate
                    mock_client.obtain_certificate.assert_called_once_with(['isnot.org'],
                        os.path.normpath(os.path.join(
                            self.config.config_dir, "live/sample-renewal/privkey.pem")))
                else:
                    mock_client.obtain_certificate.assert_called_once_with(['isnot.org'], None)
            else:
                self.assertEqual(mock_client.obtain_certificate.call_count, 0)
        except:
            self._dump_log()
            raise
        finally:
            if log_out:
                with open(os.path.join(self.config.logs_dir, "letsencrypt.log")) as lf:
                    self.assertIn(log_out, lf.read())

        return mock_lineage, mock_display, stdout

    @mock.patch('certbot._internal.main._report_new_cert')
    @mock.patch('certbot._internal.main.util.atexit_register')
    @mock.patch('certbot.crypto_util.notAfter')
    def test_certonly_renewal(self, _, mock_register, mock_report):
        lineage, _, _ = self._test_renewal_common(True, [])
        self.assertEqual(lineage.save_successor.call_count, 1)
        lineage.update_all_links_to.assert_called_once_with(
            lineage.latest_common_version())
        self.assertEqual(mock_report.call_count, 1)
        self.assertIn('fullchain.pem', mock_report.call_args[0][2])
        self.assertIn('donate', mock_register.call_args[0][1])

    @mock.patch('certbot._internal.main.display_util.notify')
    @mock.patch('certbot._internal.log.logging.handlers.RotatingFileHandler.doRollover')
    @mock.patch('certbot.crypto_util.notAfter')
    def test_certonly_renewal_triggers(self, _, __, mock_notify):
        # --dry-run should force renewal
        _, _, _ = self._test_renewal_common(False, ['--dry-run', '--keep'],
                                                      log_out="simulating renewal")
        mock_notify.assert_any_call('The dry run was successful.')

        self._test_renewal_common(False, ['--renew-by-default', '-tvv', '--debug'],
                                  log_out="Auto-renewal forced")

        _, mock_displayer, _ = self._test_renewal_common(False, ['-tvv', '--debug', '--keep'],
                                  should_renew=False)
        self.assertIn('not yet due', mock_displayer().notification.call_args[0][0])

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

    def test_reuse_key(self):
        test_util.make_lineage(self.config.config_dir, 'sample-renewal.conf')
        args = ["renew", "--dry-run", "--reuse-key"]
        self._test_renewal_common(True, [], args=args, should_renew=True, reuse_key=True)

    @mock.patch('certbot._internal.storage.RenewableCert.save_successor')
    def test_reuse_key_no_dry_run(self, unused_save_successor):
        test_util.make_lineage(self.config.config_dir, 'sample-renewal.conf')
        args = ["renew", "--reuse-key"]
        self._test_renewal_common(True, [], args=args, should_renew=True, reuse_key=True)

    @mock.patch('certbot._internal.storage.RenewableCert.save_successor')
    def test_new_key(self, unused_save_successor):
        test_util.make_lineage(self.config.config_dir, 'sample-renewal.conf')
        args = ["renew", "--reuse-key", "--new-key"]
        self._test_renewal_common(True, [], args=args, should_renew=True, reuse_key=True,
                                  new_key=True)

    @mock.patch('sys.stdin')
    def test_noninteractive_renewal_delay(self, stdin):
        stdin.isatty.return_value = False
        test_util.make_lineage(self.config.config_dir, 'sample-renewal.conf')
        args = ["renew", "--dry-run", "-tvv"]
        self._test_renewal_common(True, [], args=args, should_renew=True)
        self.assertEqual(self.mock_sleep.call_count, 1)
        # in main.py:
        #     sleep_time = random.randint(1, 60*8)
        sleep_call_arg = self.mock_sleep.call_args[0][0]
        self.assertTrue(1 <= sleep_call_arg <= 60*8)

    @mock.patch('sys.stdin')
    def test_interactive_no_renewal_delay(self, stdin):
        stdin.isatty.return_value = True
        test_util.make_lineage(self.config.config_dir, 'sample-renewal.conf')
        args = ["renew", "--dry-run", "-tvv"]
        self._test_renewal_common(True, [], args=args, should_renew=True)
        self.assertEqual(self.mock_sleep.call_count, 0)

    @mock.patch('certbot._internal.renewal.should_renew')
    def test_renew_skips_recent_certs(self, should_renew):
        should_renew.return_value = False
        test_util.make_lineage(self.config.config_dir, 'sample-renewal.conf')
        expiry = datetime.datetime.now() + datetime.timedelta(days=90)
        _, _, stdout = self._test_renewal_common(False, extra_args=None, should_renew=False,
                                                 args=['renew'], expiry_date=expiry)
        self.assertIn('No renewals were attempted.', stdout.getvalue())
        self.assertIn('The following certificates are not due for renewal yet:', stdout.getvalue())

    @mock.patch('certbot._internal.log.post_arg_parse_setup')
    def test_quiet_renew(self, _):
        test_util.make_lineage(self.config.config_dir, 'sample-renewal.conf')
        args = ["renew", "--dry-run"]
        _, _, stdout = self._test_renewal_common(True, [], args=args, should_renew=True)
        out = stdout.getvalue()
        self.assertIn("renew", out)

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
        with mock.patch("certbot._internal.hooks.post_hook"):
            self._test_renewal_common(True, [], args=args, should_renew=True,
                                      error_expected=False)

    def test_renew_verb_empty_config(self):
        rd = os.path.join(self.config.config_dir, 'renewal')
        if not os.path.exists(rd):
            filesystem.makedirs(rd)
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
        filesystem.makedirs(renewer_configs_dir)
        with open(os.path.join(renewer_configs_dir, 'test.conf'), 'w') as f:
            f.write("My contents don't matter")

    def _test_renew_common(self, renewalparams=None, names=None,
                           assert_oc_called=None, **kwargs):
        self._make_dummy_renewal_config()
        with mock.patch('certbot._internal.storage.RenewableCert') as mock_rc:
            mock_lineage = mock.MagicMock()
            mock_lineage.fullchain = "somepath/fullchain.pem"
            if renewalparams is not None:
                mock_lineage.configuration = {'renewalparams': renewalparams}
            if names is not None:
                mock_lineage.names.return_value = names
            mock_rc.return_value = mock_lineage
            with mock.patch('certbot._internal.main.renew_cert') as mock_renew_cert:
                kwargs.setdefault('args', ['renew'])
                self._test_renewal_common(True, None, should_renew=False, **kwargs)

            if assert_oc_called is not None:
                if assert_oc_called:
                    self.assertTrue(mock_renew_cert.called)
                else:
                    self.assertIs(mock_renew_cert.called, False)

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
        names = ['uniçodé.com']
        self._test_renew_common(renewalparams=renewalparams, error_expected=True,
                                names=names, assert_oc_called=False)

    @mock.patch('certbot._internal.plugins.selection.choose_configurator_plugins')
    def test_renew_with_configurator(self, mock_sel):
        mock_sel.return_value = (mock.MagicMock(), mock.MagicMock())
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
            args=['renew', '--webroot-map', json.dumps({'example.com': tempfile.gettempdir()})])

    def test_renew_reconstitute_error(self):
        # pylint: disable=protected-access
        with mock.patch('certbot._internal.main.renewal._reconstitute') as mock_reconstitute:
            mock_reconstitute.side_effect = Exception
            self._test_renew_common(assert_oc_called=False, error_expected=True)

    def test_renew_obtain_cert_error(self):
        self._make_dummy_renewal_config()
        with mock.patch('certbot._internal.storage.RenewableCert') as mock_rc:
            mock_lineage = mock.MagicMock()
            mock_lineage.fullchain = "somewhere/fullchain.pem"
            mock_rc.return_value = mock_lineage
            mock_lineage.configuration = {
                'renewalparams': {'authenticator': 'webroot'}}
            with mock.patch('certbot._internal.main.renew_cert') as mock_renew_cert:
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
            args=['renew', '--post-hook',
                  '{0} -c "print(\'hello world\');"'
                  .format(sys.executable)])
        self.assertIn('No hooks were run.', stdout.getvalue())

    @test_util.patch_display_util()
    @mock.patch('certbot._internal.main._find_lineage_for_domains_and_certname')
    @mock.patch('certbot._internal.main._init_le_client')
    @mock.patch('certbot._internal.main._report_new_cert')
    def test_certonly_reinstall(self, mock_report_new_cert, mock_init,
                                mock_renewal, mock_get_utility):
        mock_renewal.return_value = ('reinstall', mock.MagicMock())
        mock_init.return_value = mock_client = mock.MagicMock()
        self._call(['-d', 'foo.bar', '-a', 'standalone', 'certonly'])
        self.assertIs(mock_client.obtain_certificate.called, False)
        self.assertIs(mock_client.obtain_and_enroll_certificate.called, False)
        self.assertEqual(mock_get_utility().add_message.call_count, 0)
        mock_report_new_cert.assert_not_called()
        #self.assertTrue('donate' not in mock_get_utility().add_message.call_args[0][0])

    def _test_certonly_csr_common(self, extra_args=None):
        certr = 'certr'
        chain = 'chain'
        mock_client = mock.MagicMock()
        mock_client.obtain_certificate_from_csr.return_value = (certr, chain)
        cert_path = os.path.normpath(os.path.join(
            self.config.config_dir,
            'live/example.com/cert_512.pem'))
        full_path = os.path.normpath(os.path.join(
            self.config.config_dir,
            'live/example.com/fullchain.pem'))
        mock_client.save_certificate.return_value = cert_path, None, full_path
        with mock.patch('certbot._internal.main._init_le_client') as mock_init:
            mock_init.return_value = mock_client
            chain_path = os.path.normpath(os.path.join(
                self.config.config_dir,
                'live/example.com/chain.pem'))
            args = ('-a standalone certonly --csr {0} --cert-path {1} '
                    '--chain-path {2} --fullchain-path {3}').format(
                        CSR, cert_path, chain_path, full_path).split()
            if extra_args:
                args += extra_args
            with mock.patch('certbot._internal.main.crypto_util'):
                self._call(args)

        if '--dry-run' in args:
            self.assertIs(mock_client.save_certificate.called, False)
        else:
            mock_client.save_certificate.assert_called_once_with(
                certr, chain, cert_path, chain_path, full_path)

    @mock.patch('certbot._internal.main._csr_report_new_cert')
    @mock.patch('certbot._internal.main.util.atexit_register')
    @mock.patch('certbot._internal.eff.handle_subscription')
    def test_certonly_csr(self, mock_subscription, mock_register, mock_csr_report):
        self._test_certonly_csr_common()
        self.assertEqual(mock_csr_report.call_count, 1)
        self.assertIn('cert_512.pem', mock_csr_report.call_args[0][1])
        self.assertIsNone(mock_csr_report.call_args[0][2])
        self.assertIn('fullchain.pem', mock_csr_report.call_args[0][3])
        self.assertIn('donate', mock_register.call_args[0][1])
        self.assertIs(mock_subscription.called, True)

    @mock.patch('certbot._internal.main._csr_report_new_cert')
    def test_certonly_csr_dry_run(self, mock_csr_report):
        self._test_certonly_csr_common(['--dry-run'])
        self.assertEqual(mock_csr_report.call_count, 1)
        self.assertIs(mock_csr_report.call_args[0][0].dry_run, True)

    @mock.patch('certbot._internal.main._delete_if_appropriate')
    @mock.patch('certbot._internal.main.client.acme_client')
    def test_revoke_with_key(self, mock_acme_client,
            mock_delete_if_appropriate):
        mock_delete_if_appropriate.return_value = False
        server = 'foo.bar'
        self._call_no_clientmock(['--cert-path', SS_CERT_PATH, '--key-path', RSA2048_KEY_PATH,
                                 '--server', server, 'revoke'])
        with open(RSA2048_KEY_PATH, 'rb') as f:
            mock_acme_client.BackwardsCompatibleClientV2.assert_called_once_with(
                mock.ANY, jose.JWK.load(f.read()), server)
        with open(SS_CERT_PATH, 'rb') as f:
            cert = crypto_util.pyopenssl_load_certificate(f.read())[0]
            mock_revoke = mock_acme_client.BackwardsCompatibleClientV2().revoke
            mock_revoke.assert_called_once_with(
                    jose.ComparableX509(cert),
                    mock.ANY)

    def test_revoke_with_key_mismatch(self):
        server = 'foo.bar'
        self.assertRaises(errors.Error, self._call_no_clientmock,
            ['--cert-path', CERT, '--key-path', KEY,
                                 '--server', server, 'revoke'])

    @mock.patch('certbot._internal.main._delete_if_appropriate')
    @mock.patch('certbot._internal.main._determine_account')
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

    @mock.patch('certbot._internal.log.post_arg_parse_setup')
    def test_register(self, _):
        with mock.patch('certbot._internal.main.client') as mocked_client:
            acc = mock.MagicMock()
            acc.id = "imaginary_account"
            mocked_client.register.return_value = (acc, "worked")
            self._call_no_clientmock(["register", "--email", "user@example.org"])
            # TODO: It would be more correct to explicitly check that
            #       _determine_account() gets called in the above case,
            #       but coverage statistics should also show that it did.
            with mock.patch('certbot._internal.main.account') as mocked_account:
                mocked_storage = mock.MagicMock()
                mocked_account.AccountFileStorage.return_value = mocked_storage
                mocked_storage.find_all.return_value = ["an account"]
                x = self._call_no_clientmock(["register", "--email", "user@example.org"])
                self.assertIn("There is an existing account", x[0])

    @mock.patch('certbot._internal.plugins.selection.choose_configurator_plugins')
    @mock.patch('certbot._internal.updater._run_updaters')
    def test_plugin_selection_error(self, mock_run, mock_choose):
        mock_choose.side_effect = errors.PluginSelectionError
        self.assertRaises(errors.PluginSelectionError, main.renew_cert,
                          None, None, None)

        self.config.dry_run = False
        updater.run_generic_updaters(self.config, None, None)
        # Make sure we're returning None, and hence not trying to run the
        # without installer
        self.assertIs(mock_run.called, False)

    @mock.patch('certbot._internal.main.updater.run_renewal_deployer')
    @mock.patch('certbot._internal.plugins.selection.choose_configurator_plugins')
    @mock.patch('certbot._internal.main._init_le_client')
    @mock.patch('certbot._internal.main._get_and_save_cert')
    def test_renew_doesnt_restart_on_dryrun(self, mock_get_cert, mock_init, mock_choose,
                                            mock_run_renewal_deployer):
        """A dry-run renewal shouldn't try to restart the installer"""
        self.config.dry_run = True
        installer = mock.MagicMock()
        mock_choose.return_value = (installer, mock.MagicMock())

        main.renew_cert(self.config, None, None)

        self.assertEqual(mock_init.call_count, 1)
        self.assertEqual(mock_get_cert.call_count, 1)
        installer.restart.assert_not_called()
        mock_run_renewal_deployer.assert_not_called()


class UnregisterTest(unittest.TestCase):
    def setUp(self):
        self.patchers = {
            '_determine_account': mock.patch('certbot._internal.main._determine_account'),
            'account': mock.patch('certbot._internal.main.account'),
            'client': mock.patch('certbot._internal.main.client'),
            'get_utility': test_util.patch_display_util()}
        self.mocks = {k: v.start() for k, v in self.patchers.items()}

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

    @mock.patch("certbot._internal.main.display_util.notify")
    def test_unregister(self, mock_notify):
        mocked_storage = mock.MagicMock()
        mocked_storage.find_all.return_value = ["an account"]

        self.mocks['account'].AccountFileStorage.return_value = mocked_storage
        self.mocks['_determine_account'].return_value = (mock.MagicMock(), "foo")

        cb_client = mock.MagicMock()
        self.mocks['client'].Client.return_value = cb_client

        config = mock.MagicMock()
        unused_plugins = mock.MagicMock()

        res = main.unregister(config, unused_plugins)

        self.assertIsNone(res)
        mock_notify.assert_called_once_with("Account deactivated.")

    def test_unregister_no_account(self):
        mocked_storage = mock.MagicMock()
        mocked_storage.find_all.return_value = []
        self.mocks['account'].AccountFileStorage.return_value = mocked_storage

        cb_client = mock.MagicMock()
        self.mocks['client'].Client.return_value = cb_client

        config = mock.MagicMock()
        config.server = "https://acme.example.com/directory"
        unused_plugins = mock.MagicMock()

        res = main.unregister(config, unused_plugins)
        m = "Could not find existing account for server https://acme.example.com/directory."
        self.assertEqual(res, m)
        self.assertIs(cb_client.acme.deactivate_registration.called, False)


class MakeOrVerifyNeededDirs(test_util.ConfigTestCase):
    """Tests for certbot._internal.main.make_or_verify_needed_dirs."""

    @mock.patch("certbot._internal.main.util")
    def test_it(self, mock_util):
        main.make_or_verify_needed_dirs(self.config)
        for core_dir in (self.config.config_dir, self.config.work_dir,):
            mock_util.set_up_core_dir.assert_any_call(
                core_dir, constants.CONFIG_DIRS_MODE,
                self.config.strict_permissions
            )

        hook_dirs = (self.config.renewal_pre_hooks_dir,
                     self.config.renewal_deploy_hooks_dir,
                     self.config.renewal_post_hooks_dir,)
        for hook_dir in hook_dirs:
            # default mode of 755 is used
            mock_util.make_or_verify_dir.assert_any_call(
                hook_dir, strict=self.config.strict_permissions)


class EnhanceTest(test_util.ConfigTestCase):
    """Tests for certbot._internal.main.enhance."""

    def setUp(self):
        super().setUp()
        self.get_utility_patch = test_util.patch_display_util()
        self.mock_get_utility = self.get_utility_patch.start()
        self.mockinstaller = mock.MagicMock(spec=enhancements.AutoHSTSEnhancement)

    def tearDown(self):
        self.get_utility_patch.stop()

    def _call(self, args):
        plugins = disco.PluginsRegistry.find_all()
        config = configuration.NamespaceConfig(
            cli.prepare_and_parse_args(plugins, args))

        with mock.patch('certbot._internal.cert_manager.get_certnames') as mock_certs:
            mock_certs.return_value = ['example.com']
            with mock.patch('certbot._internal.cert_manager.domains_for_certname') as mock_dom:
                mock_dom.return_value = ['example.com']
                with mock.patch('certbot._internal.main._init_le_client') as mock_init:
                    mock_client = mock.MagicMock()
                    mock_client.config = config
                    mock_init.return_value = mock_client
                    main.enhance(config, plugins)
                    return mock_client # returns the client

    @mock.patch('certbot._internal.main.plug_sel.record_chosen_plugins')
    @mock.patch('certbot._internal.cert_manager.lineage_for_certname')
    @mock.patch('certbot._internal.main.display_ops.choose_values')
    @mock.patch('certbot._internal.main._find_domains_or_certname')
    def test_selection_question(self, mock_find, mock_choose, mock_lineage, _rec):
        mock_lineage.return_value = mock.MagicMock(chain_path="/tmp/nonexistent")
        mock_choose.return_value = ['example.com']
        mock_find.return_value = (None, None)
        with mock.patch('certbot._internal.main.plug_sel.pick_installer') as mock_pick:
            self._call(['enhance', '--redirect'])
            self.assertTrue(mock_pick.called)
            # Check that the message includes "enhancements"
            self.assertIn("enhancements", mock_pick.call_args[0][3])

    @mock.patch('certbot._internal.main.plug_sel.record_chosen_plugins')
    @mock.patch('certbot._internal.cert_manager.lineage_for_certname')
    @mock.patch('certbot._internal.main.display_ops.choose_values')
    @mock.patch('certbot._internal.main._find_domains_or_certname')
    def test_selection_auth_warning(self, mock_find, mock_choose, mock_lineage, _rec):
        mock_lineage.return_value = mock.MagicMock(chain_path="/tmp/nonexistent")
        mock_choose.return_value = ["example.com"]
        mock_find.return_value = (None, None)
        with mock.patch('certbot._internal.main.plug_sel.pick_installer'):
            with mock.patch('certbot._internal.main.plug_sel.logger.warning') as mock_log:
                mock_client = self._call(['enhance', '-a', 'webroot', '--redirect'])
                self.assertTrue(mock_log.called)
                self.assertIn("make sense", mock_log.call_args[0][0])
                self.assertTrue(mock_client.enhance_config.called)

    @mock.patch('certbot._internal.cert_manager.lineage_for_certname')
    @mock.patch('certbot._internal.main.display_ops.choose_values')
    @mock.patch('certbot._internal.main.plug_sel.record_chosen_plugins')
    def test_enhance_config_call(self, _rec, mock_choose, mock_lineage):
        mock_lineage.return_value = mock.MagicMock(chain_path="/tmp/nonexistent")
        mock_choose.return_value = ["example.com"]
        with mock.patch('certbot._internal.main.plug_sel.pick_installer'):
            mock_client = self._call(['enhance', '--redirect', '--hsts'])
            req_enh = ["redirect", "hsts"]
            not_req_enh = ["uir"]
            self.assertTrue(mock_client.enhance_config.called)
            self.assertTrue(
                all(getattr(mock_client.config, e) for e in req_enh))
            self.assertFalse(
                any(getattr(mock_client.config, e) for e in not_req_enh))
            self.assertIn(
                "example.com", mock_client.enhance_config.call_args[0][0])

    @mock.patch('certbot._internal.cert_manager.lineage_for_certname')
    @mock.patch('certbot._internal.main.display_ops.choose_values')
    @mock.patch('certbot._internal.main.plug_sel.record_chosen_plugins')
    def test_enhance_noninteractive(self, _rec, mock_choose, mock_lineage):
        mock_lineage.return_value = mock.MagicMock(
            chain_path="/tmp/nonexistent")
        mock_choose.return_value = ["example.com"]
        with mock.patch('certbot._internal.main.plug_sel.pick_installer'):
            mock_client = self._call(['enhance', '--redirect',
                                      '--hsts', '--non-interactive'])
            self.assertTrue(mock_client.enhance_config.called)
            self.assertIs(mock_choose.called, False)

    @mock.patch('certbot._internal.main.display_ops.choose_values')
    @mock.patch('certbot._internal.main.plug_sel.record_chosen_plugins')
    def test_user_abort_domains(self, _rec, mock_choose):
        mock_choose.return_value = []
        with mock.patch('certbot._internal.main.plug_sel.pick_installer'):
            self.assertRaises(errors.Error,
                              self._call,
                              ['enhance', '--redirect', '--hsts'])

    def test_no_enhancements_defined(self):
        self.assertRaises(errors.MisconfigurationError,
                          self._call, ['enhance', '-a', 'null'])

    @mock.patch('certbot._internal.main.plug_sel.choose_configurator_plugins')
    @mock.patch('certbot._internal.main.display_ops.choose_values')
    @mock.patch('certbot._internal.main.plug_sel.record_chosen_plugins')
    def test_plugin_selection_error(self, _rec, mock_choose, mock_pick):
        mock_choose.return_value = ["example.com"]
        mock_pick.return_value = (None, None)
        mock_pick.side_effect = errors.PluginSelectionError()
        mock_client = self._call(['enhance', '--hsts'])
        self.assertIs(mock_client.enhance_config.called, False)

    @mock.patch('certbot._internal.cert_manager.lineage_for_certname')
    @mock.patch('certbot._internal.main.display_ops.choose_values')
    @mock.patch('certbot._internal.main.plug_sel.pick_installer')
    @mock.patch('certbot._internal.main.plug_sel.record_chosen_plugins')
    @test_util.patch_display_util()
    def test_enhancement_enable(self, _, _rec, mock_inst, mock_choose, mock_lineage):
        mock_inst.return_value = self.mockinstaller
        mock_choose.return_value = ["example.com", "another.tld"]
        mock_lineage.return_value = mock.MagicMock(chain_path="/tmp/nonexistent")
        self._call(['enhance', '--auto-hsts'])
        self.assertTrue(self.mockinstaller.enable_autohsts.called)
        self.assertEqual(self.mockinstaller.enable_autohsts.call_args[0][1],
                          ["example.com", "another.tld"])

    @mock.patch('certbot._internal.cert_manager.lineage_for_certname')
    @mock.patch('certbot._internal.main.display_ops.choose_values')
    @mock.patch('certbot._internal.main.plug_sel.pick_installer')
    @mock.patch('certbot._internal.main.plug_sel.record_chosen_plugins')
    @test_util.patch_display_util()
    def test_enhancement_enable_not_supported(self, _, _rec, mock_inst, mock_choose, mock_lineage):
        mock_inst.return_value = null.Installer(self.config, "null")
        mock_choose.return_value = ["example.com", "another.tld"]
        mock_lineage.return_value = mock.MagicMock(chain_path="/tmp/nonexistent")
        self.assertRaises(
            errors.NotSupportedError,
            self._call, ['enhance', '--auto-hsts'])

    def test_enhancement_enable_conflict(self):
        self.assertRaises(
            errors.Error,
            self._call, ['enhance', '--auto-hsts', '--hsts'])


class InstallTest(test_util.ConfigTestCase):
    """Tests for certbot._internal.main.install."""

    def setUp(self):
        super().setUp()
        self.mockinstaller = mock.MagicMock(spec=enhancements.AutoHSTSEnhancement)

    @mock.patch('certbot._internal.main.plug_sel.record_chosen_plugins')
    @mock.patch('certbot._internal.main.plug_sel.pick_installer')
    def test_install_enhancement_not_supported(self, mock_inst, _rec):
        mock_inst.return_value = null.Installer(self.config, "null")
        plugins = disco.PluginsRegistry.find_all()
        self.config.auto_hsts = True
        self.config.certname = "nonexistent"
        self.assertRaises(errors.NotSupportedError,
                          main.install,
                          self.config, plugins)

    @mock.patch('certbot._internal.main.plug_sel.record_chosen_plugins')
    @mock.patch('certbot._internal.main.plug_sel.pick_installer')
    def test_install_enhancement_no_certname(self, mock_inst, _rec):
        mock_inst.return_value = self.mockinstaller
        plugins = disco.PluginsRegistry.find_all()
        self.config.auto_hsts = True
        self.config.certname = None
        self.config.key_path = "/tmp/nonexistent"
        self.config.cert_path = "/tmp/nonexistent"
        self.assertRaises(errors.ConfigurationError,
                          main.install,
                          self.config, plugins)


class ReportNewCertTest(unittest.TestCase):
    """Tests for certbot._internal.main._report_new_cert and
       certbot._internal.main._csr_report_new_cert.
    """

    def setUp(self):
        from datetime import datetime
        self.notify_patch = mock.patch('certbot._internal.main.display_util.notify')
        self.mock_notify = self.notify_patch.start()

        self.notafter_patch = mock.patch('certbot._internal.main.crypto_util.notAfter')
        self.mock_notafter = self.notafter_patch.start()
        self.mock_notafter.return_value = datetime.utcfromtimestamp(0)

    def tearDown(self):
        self.notify_patch.stop()
        self.notafter_patch.stop()

    @classmethod
    def _call(cls, *args, **kwargs):
        from certbot._internal.main import _report_new_cert
        return _report_new_cert(*args, **kwargs)

    @classmethod
    def _call_csr(cls, *args, **kwargs):
        from certbot._internal.main import _csr_report_new_cert
        return _csr_report_new_cert(*args, **kwargs)

    def test_report_dry_run(self):
        self._call(mock.Mock(dry_run=True), None, None, None)
        self.mock_notify.assert_called_with("The dry run was successful.")

    def test_csr_report_dry_run(self):
        self._call_csr(mock.Mock(dry_run=True), None, None, None)
        self.mock_notify.assert_called_with("The dry run was successful.")

    def test_report_no_paths(self):
        with self.assertRaises(AssertionError):
            self._call(mock.Mock(dry_run=False), None, None, None)

        with self.assertRaises(AssertionError):
            self._call_csr(mock.Mock(dry_run=False), None, None, None)

    def test_report(self):
        self._call(mock.Mock(dry_run=False),
                  '/path/to/cert.pem', '/path/to/fullchain.pem',
                  '/path/to/privkey.pem')

        self.mock_notify.assert_called_with(
            '\nSuccessfully received certificate.\n'
            'Certificate is saved at: /path/to/fullchain.pem\n'
            'Key is saved at:         /path/to/privkey.pem\n'
            'This certificate expires on 1970-01-01.\n'
            'These files will be updated when the certificate renews.\n'
            'Certbot has set up a scheduled task to automatically renew this '
            'certificate in the background.'
        )

    def test_report_no_key(self):
        self._call(mock.Mock(dry_run=False),
                  '/path/to/cert.pem', '/path/to/fullchain.pem',
                  None)

        self.mock_notify.assert_called_with(
            '\nSuccessfully received certificate.\n'
            'Certificate is saved at: /path/to/fullchain.pem\n'
            'This certificate expires on 1970-01-01.\n'
            'These files will be updated when the certificate renews.\n'
            'Certbot has set up a scheduled task to automatically renew this '
            'certificate in the background.'
        )

    def test_report_no_preconfigured_renewal(self):
        self._call(mock.Mock(dry_run=False, preconfigured_renewal=False),
                  '/path/to/cert.pem', '/path/to/fullchain.pem',
                  '/path/to/privkey.pem')

        self.mock_notify.assert_called_with(
            '\nSuccessfully received certificate.\n'
            'Certificate is saved at: /path/to/fullchain.pem\n'
            'Key is saved at:         /path/to/privkey.pem\n'
            'This certificate expires on 1970-01-01.\n'
            'These files will be updated when the certificate renews.'
        )

    def test_csr_report(self):
        self._call_csr(mock.Mock(dry_run=False), '/path/to/cert.pem',
                      '/path/to/chain.pem', '/path/to/fullchain.pem')

        self.mock_notify.assert_called_with(
            '\nSuccessfully received certificate.\n'
            'Certificate is saved at:            /path/to/cert.pem\n'
            'Intermediate CA chain is saved at:  /path/to/chain.pem\n'
            'Full certificate chain is saved at: /path/to/fullchain.pem\n'
            'This certificate expires on 1970-01-01.'
        )

    def test_manual_no_hooks_report(self):
        """Shouldn't get a message about autorenewal if no --manual-auth-hook"""
        self._call(mock.Mock(dry_run=False, authenticator='manual', manual_auth_hook=None),
                  '/path/to/cert.pem', '/path/to/fullchain.pem',
                  '/path/to/privkey.pem')

        self.mock_notify.assert_called_with(
            '\nSuccessfully received certificate.\n'
            'Certificate is saved at: /path/to/fullchain.pem\n'
            'Key is saved at:         /path/to/privkey.pem\n'
            'This certificate expires on 1970-01-01.\n'
            'These files will be updated when the certificate renews.'
        )


class ReportNextStepsTest(unittest.TestCase):
    """Tests for certbot._internal.main._report_next_steps"""

    def setUp(self):
        self.config = mock.MagicMock(
            cert_name="example.com", preconfigured_renewal=True,
            csr=None, authenticator="nginx", manual_auth_hook=None)
        notify_patch = mock.patch('certbot._internal.main.display_util.notify')
        self.mock_notify = notify_patch.start()
        self.addCleanup(notify_patch.stop)
        self.old_stdout = sys.stdout
        sys.stdout = io.StringIO()

    def tearDown(self):
        sys.stdout = self.old_stdout

    @classmethod
    def _call(cls, *args, **kwargs):
        from certbot._internal.main import _report_next_steps
        _report_next_steps(*args, **kwargs)

    def _output(self) -> str:
        self.assertEqual(self.mock_notify.call_count, 2)
        self.assertEqual(self.mock_notify.call_args_list[0][0][0], 'NEXT STEPS:')
        return self.mock_notify.call_args_list[1][0][0]

    def test_report(self):
        """No steps for a normal renewal"""
        self.config.authenticator = "manual"
        self.config.manual_auth_hook = "/bin/true"
        self._call(self.config, None, None)
        self.mock_notify.assert_not_called()

    def test_csr_report(self):
        """--csr requires manual renewal"""
        self.config.csr = "foo.csr"
        self._call(self.config, None, None)
        self.assertIn("--csr will not be renewed", self._output())

    def test_manual_no_hook_renewal(self):
        """--manual without a hook requires manual renewal"""
        self.config.authenticator = "manual"
        self._call(self.config, None, None)
        self.assertIn("--manual certificates requires", self._output())

    def test_no_preconfigured_renewal(self):
        """No --preconfigured-renewal needs manual cron setup"""
        self.config.preconfigured_renewal = False
        self._call(self.config, None, None)
        self.assertIn("https://certbot.org/renewal-setup", self._output())


class UpdateAccountTest(test_util.ConfigTestCase):
    """Tests for certbot._internal.main.update_account"""

    def setUp(self):
        patches = {
            'account': mock.patch('certbot._internal.main.account'),
            'atexit': mock.patch('certbot.util.atexit'),
            'client': mock.patch('certbot._internal.main.client'),
            'determine_account': mock.patch('certbot._internal.main._determine_account'),
            'notify': mock.patch('certbot._internal.main.display_util.notify'),
            'prepare_sub': mock.patch('certbot._internal.eff.prepare_subscription'),
            'util': test_util.patch_display_util()
        }
        self.mocks = { k: patches[k].start() for k in patches }
        for patch in patches.values():
            self.addCleanup(patch.stop)

        return super().setUp()

    def _call(self, args):
        with mock.patch('certbot._internal.main.sys.stdout'), \
             mock.patch('certbot._internal.main.sys.stderr'):
            args = ['--config-dir', self.config.config_dir,
                    '--work-dir', self.config.work_dir,
                    '--logs-dir', self.config.logs_dir, '--text'] + args
            return main.main(args[:]) # NOTE: parser can alter its args!

    def _prepare_mock_account(self):
        mock_storage = mock.MagicMock()
        mock_account = mock.MagicMock()
        mock_regr = mock.MagicMock()
        mock_storage.find_all.return_value = [mock_account]
        self.mocks['account'].AccountFileStorage.return_value = mock_storage
        mock_account.regr.body = mock_regr.body
        self.mocks['determine_account'].return_value = (mock_account, mock.MagicMock())
        return (mock_account, mock_storage, mock_regr)

    def _test_update_no_contact(self, args):
        """Utility to assert that email removal is handled correctly"""
        (_, mock_storage, mock_regr) = self._prepare_mock_account()
        result = self._call(args)
        # When update succeeds, the return value of update_account() is None
        self.assertIsNone(result)
        # We submitted a registration to the server
        self.assertEqual(self.mocks['client'].Client().acme.update_registration.call_count, 1)
        mock_regr.body.update.assert_called_with(contact=())
        # We got an update from the server and persisted it
        self.assertEqual(mock_storage.update_regr.call_count, 1)
        # We should have notified the user
        self.mocks['notify'].assert_called_with(
            'Any contact information associated with this account has been removed.'
        )
        # We should not have called subscription because there's no email
        self.mocks['prepare_sub'].assert_not_called()

    def test_no_existing_accounts(self):
        """Test that no existing account is handled correctly"""
        mock_storage = mock.MagicMock()
        mock_storage.find_all.return_value = []
        self.mocks['account'].AccountFileStorage.return_value = mock_storage
        self.assertEqual(self._call(['update_account', '--email', 'user@example.org']),
                         'Could not find an existing account for server'
                         ' https://acme-v02.api.letsencrypt.org/directory.')

    def test_update_account_remove_email(self):
        """Test that --register-unsafely-without-email is handled as no email"""
        self._test_update_no_contact(['update_account', '--register-unsafely-without-email'])

    def test_update_account_empty_email(self):
        """Test that providing an empty email is handled as no email"""
        self._test_update_no_contact(['update_account', '-m', ''])

    @mock.patch('certbot._internal.main.display_ops.get_email')
    def test_update_account_with_email(self, mock_email):
        """Test that updating with a singular email is handled correctly"""
        mock_email.return_value = 'user@example.com'
        (_, mock_storage, _) = self._prepare_mock_account()
        mock_client = mock.MagicMock()
        self.mocks['client'].Client.return_value = mock_client

        result = self._call(['update_account'])
        # None if registration succeeds
        self.assertIsNone(result)
        # We should have updated the server
        self.assertEqual(mock_client.acme.update_registration.call_count, 1)
        # We should have updated the account on disk
        self.assertEqual(mock_storage.update_regr.call_count, 1)
        # Subscription should have been prompted
        self.assertEqual(self.mocks['prepare_sub'].call_count, 1)
        # Should have printed the email
        self.mocks['notify'].assert_called_with(
            'Your e-mail address was updated to user@example.com.')

    def test_update_account_with_multiple_emails(self):
        """Test that multiple email addresses are handled correctly"""
        (_, mock_storage, mock_regr) = self._prepare_mock_account()
        self.assertIsNone(
            self._call(['update_account', '-m', 'user@example.com,user@example.org'])
        )
        mock_regr.body.update.assert_called_with(
            contact=['mailto:user@example.com', 'mailto:user@example.org']
        )
        self.assertEqual(mock_storage.update_regr.call_count, 1)
        self.mocks['notify'].assert_called_with(
            'Your e-mail address was updated to user@example.com,user@example.org.')


class ShowAccountTest(test_util.ConfigTestCase):
    """Tests for certbot._internal.main.show_account"""

    def setUp(self):
        patches = {
            'account': mock.patch('certbot._internal.main.account'),
            'atexit': mock.patch('certbot.util.atexit'),
            'client': mock.patch('certbot._internal.main.client'),
            'determine_account': mock.patch('certbot._internal.main._determine_account'),
            'notify': mock.patch('certbot._internal.main.display_util.notify'),
            'util': test_util.patch_display_util()
        }
        self.mocks = { k: patches[k].start() for k in patches }
        for patch in patches.values():
            self.addCleanup(patch.stop)

        return super().setUp()

    def _call(self, args):
        with mock.patch('certbot._internal.main.sys.stdout'), \
             mock.patch('certbot._internal.main.sys.stderr'):
            args = ['--config-dir', self.config.config_dir,
                    '--work-dir', self.config.work_dir,
                    '--logs-dir', self.config.logs_dir, '--text'] + args
            return main.main(args[:]) # NOTE: parser can alter its args!

    def _prepare_mock_account(self):
        mock_storage = mock.MagicMock()
        mock_account = mock.MagicMock()
        mock_regr = mock.MagicMock()
        mock_storage.find_all.return_value = [mock_account]
        self.mocks['account'].AccountFileStorage.return_value = mock_storage
        mock_account.regr.body = mock_regr.body
        self.mocks['determine_account'].return_value = (mock_account, mock.MagicMock())

    def _test_show_account(self, contact):
        self._prepare_mock_account()
        mock_client = mock.MagicMock()
        mock_regr = mock.MagicMock()
        mock_regr.body.contact = contact
        mock_regr.uri = 'https://www.letsencrypt-demo.org/acme/reg/1'
        mock_regr.body.key.thumbprint.return_value = b'foobarbaz'
        mock_client.acme.query_registration.return_value = mock_regr
        self.mocks['client'].Client.return_value = mock_client

        args = ['show_account']

        self._call(args)

        self.assertEqual(mock_client.acme.query_registration.call_count, 1)

    def test_no_existing_accounts(self):
        """Test that no existing account is handled correctly"""
        mock_storage = mock.MagicMock()
        mock_storage.find_all.return_value = []
        self.mocks['account'].AccountFileStorage.return_value = mock_storage
        self.assertEqual(self._call(['show_account']),
                         'Could not find an existing account for server'
                         ' https://acme-v02.api.letsencrypt.org/directory.')

    def test_no_existing_client(self):
        """Test that issues with the ACME client are handled correctly"""
        self._prepare_mock_account()
        mock_client = mock.MagicMock()
        mock_client.acme = None
        self.mocks['client'].Client.return_value = mock_client
        try:
            self._call(['show_account'])
        except errors.Error as e:
            self.assertEqual('ACME client is not set.', str(e))

    def test_no_contacts(self):
        self._test_show_account(())

        self.assertEqual(self.mocks['notify'].call_count, 1)
        self.mocks['notify'].assert_has_calls([
            mock.call('Account details for server https://acme-v02.api.letsencr'
                      'ypt.org/directory:\n  Account URL: https://www.letsencry'
                      'pt-demo.org/acme/reg/1\n  Email contact: none')])

    def test_single_email(self):
        contact = ('mailto:foo@example.com',)
        self._test_show_account(contact)

        self.assertEqual(self.mocks['notify'].call_count, 1)
        self.mocks['notify'].assert_has_calls([
            mock.call('Account details for server https://acme-v02.api.letsencr'
                      'ypt.org/directory:\n  Account URL: https://www.letsencry'
                      'pt-demo.org/acme/reg/1\n  Email contact: foo@example.com')])

    def test_double_email(self):
        contact = ('mailto:foo@example.com', 'mailto:bar@example.com')
        self._test_show_account(contact)

        self.assertEqual(self.mocks['notify'].call_count, 1)
        self.mocks['notify'].assert_has_calls([
            mock.call('Account details for server https://acme-v02.api.letsencr'
                      'ypt.org/directory:\n  Account URL: https://www.letsencry'
                      'pt-demo.org/acme/reg/1\n  Email contacts: foo@example.com, bar@example.com')])


if __name__ == '__main__':
    unittest.main()  # pragma: no cover
