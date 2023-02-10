"""Tests for certbot._internal.client."""
import contextlib
import datetime
import platform
import shutil
import tempfile
import unittest
from unittest import mock
from unittest.mock import MagicMock

from josepy import interfaces

from certbot import errors
from certbot import util
from certbot._internal import account
from certbot._internal import constants
from certbot._internal.display import obj as display_obj
from certbot.compat import os
import certbot.tests.util as test_util

KEY = test_util.load_vector("rsa512_key.pem")
CSR_SAN = test_util.load_vector("csr-san_512.pem")

# pylint: disable=line-too-long


class DetermineUserAgentTest(test_util.ConfigTestCase):
    """Tests for certbot._internal.client.determine_user_agent."""

    def _call(self):
        from certbot._internal.client import determine_user_agent
        return determine_user_agent(self.config)

    @mock.patch.dict(os.environ, {"CERTBOT_DOCS": "1"})
    def test_docs_value(self):
        self._test(expect_doc_values=True)

    @mock.patch.dict(os.environ, {})
    def test_real_values(self):
        self._test(expect_doc_values=False)

    def _test(self, expect_doc_values):
        ua = self._call()

        if expect_doc_values:
            doc_value_check = self.assertIn
            real_value_check = self.assertNotIn
        else:
            doc_value_check = self.assertNotIn
            real_value_check = self.assertIn

        doc_value_check("OS_NAME OS_VERSION", ua)
        doc_value_check("major.minor.patchlevel", ua)
        real_value_check(util.get_os_info_ua(), ua)
        real_value_check(platform.python_version(), ua)


class RegisterTest(test_util.ConfigTestCase):
    """Tests for certbot._internal.client.register."""

    def setUp(self):
        super().setUp()
        self.config.rsa_key_size = 1024
        self.config.register_unsafely_without_email = False
        self.config.email = "alias@example.com"
        self.account_storage = account.AccountMemoryStorage()
        self.tos_cb = mock.MagicMock()
        display_obj.set_display(MagicMock())

    def _call(self):
        from certbot._internal.client import register
        return register(self.config, self.account_storage, self.tos_cb)

    @staticmethod
    def _public_key_mock():
        m = mock.Mock(__class__=interfaces.JSONDeSerializable)
        m.to_partial_json.return_value = '{"a": 1}'
        return m

    @staticmethod
    def _new_acct_dir_mock():
        return "/acme/new-account"

    @staticmethod
    def _true_mock():
        return True

    @staticmethod
    def _false_mock():
        return False

    @staticmethod
    @contextlib.contextmanager
    def _patched_acme_client():
        with mock.patch('certbot._internal.client.acme_client') as mock_acme_client:
            yield mock_acme_client.ClientV2

    def test_no_tos(self):
        with self._patched_acme_client() as mock_client:
            mock_client.new_account().terms_of_service = "http://tos"
            mock_client().external_account_required.side_effect = self._false_mock
            with mock.patch("certbot._internal.eff.prepare_subscription") as mock_prepare:
                mock_client().new_account.side_effect = errors.Error
                self.assertRaises(errors.Error, self._call)
                self.assertIs(mock_prepare.called, False)

                mock_client().new_account.side_effect = None
                self._call()
                self.assertIs(mock_prepare.called, True)

    @mock.patch('certbot._internal.eff.prepare_subscription')
    def test_empty_meta(self, unused_mock_prepare):
        # Test that we can handle an ACME server which does not implement the 'meta'
        # directory object (for terms-of-service handling).
        with self._patched_acme_client() as mock_client:
            from acme.messages import Directory
            mock_client().directory = Directory.from_json({})

            mock_client().external_account_required.side_effect = self._false_mock

            self._call()
            self.assertIs(self.tos_cb.called, False)

    @test_util.patch_display_util()
    def test_it(self, unused_mock_get_utility):
        with self._patched_acme_client() as mock_client:
            mock_client().external_account_required.side_effect = self._false_mock
            with mock.patch("certbot._internal.eff.handle_subscription"):
                self._call()
            self.assertIs(self.tos_cb.called, True)

    @mock.patch("certbot._internal.client.display_ops.get_email")
    def test_email_retry(self, mock_get_email):
        from acme import messages
        self.config.noninteractive_mode = False
        msg = "DNS problem: NXDOMAIN looking up MX for example.com"
        mx_err = messages.Error.with_code('invalidContact', detail=msg)
        with self._patched_acme_client() as mock_client:
            mock_client().external_account_required.side_effect = self._false_mock
            with mock.patch("certbot._internal.eff.prepare_subscription") as mock_prepare:
                mock_client().new_account.side_effect = [mx_err, mock.MagicMock()]
                self._call()
                self.assertEqual(mock_get_email.call_count, 1)
                self.assertIs(mock_prepare.called, True)

    def test_email_invalid_noninteractive(self):
        from acme import messages
        self.config.noninteractive_mode = True
        msg = "DNS problem: NXDOMAIN looking up MX for example.com"
        mx_err = messages.Error.with_code('invalidContact', detail=msg)
        with self._patched_acme_client() as mock_client:
            mock_client().external_account_required.side_effect = self._false_mock
            with mock.patch("certbot._internal.eff.handle_subscription"):
                mock_client().new_account.side_effect = [mx_err, mock.MagicMock()]
                self.assertRaises(errors.Error, self._call)

    def test_needs_email(self):
        self.config.email = None
        self.assertRaises(errors.Error, self._call)

    @mock.patch("certbot._internal.client.logger")
    def test_without_email(self, mock_logger):
        with mock.patch("certbot._internal.eff.prepare_subscription") as mock_prepare:
            with self._patched_acme_client() as mock_client:
                mock_client().external_account_required.side_effect = self._false_mock
                self.config.email = None
                self.config.register_unsafely_without_email = True
                self.config.dry_run = False
                self._call()
                mock_logger.debug.assert_called_once_with(mock.ANY)
                self.assertIs(mock_prepare.called, True)

    @mock.patch("certbot._internal.client.display_ops.get_email")
    def test_dry_run_no_staging_account(self, mock_get_email):
        """Tests dry-run for no staging account, expect account created with no email"""
        with self._patched_acme_client() as mock_client:
            mock_client().external_account_required.side_effect = self._false_mock
            with mock.patch("certbot._internal.eff.handle_subscription"):
                self.config.dry_run = True
                self._call()
                # check Certbot did not ask the user to provide an email
                self.assertIs(mock_get_email.called, False)
                # check Certbot created an account with no email. Contact should return empty
                self.assertFalse(mock_client().new_account.call_args[0][0].contact)

    @test_util.patch_display_util()
    def test_with_eab_arguments(self, unused_mock_get_utility):
        with self._patched_acme_client() as mock_client:
            mock_client().client.directory.__getitem__ = mock.Mock(
                side_effect=self._new_acct_dir_mock
            )
            mock_client().external_account_required.side_effect = self._false_mock
            with mock.patch("certbot._internal.eff.handle_subscription"):
                target = "certbot._internal.client.messages.ExternalAccountBinding.from_data"
                with mock.patch(target) as mock_eab_from_data:
                    self.config.eab_kid = "test-kid"
                    self.config.eab_hmac_key = "J2OAqW4MHXsrHVa_PVg0Y-L_R4SYw0_aL1le6mfblbE"
                    self._call()

                    self.assertIs(mock_eab_from_data.called, True)

    @test_util.patch_display_util()
    def test_without_eab_arguments(self, unused_mock_get_utility):
        with self._patched_acme_client() as mock_client:
            mock_client().external_account_required.side_effect = self._false_mock
            with mock.patch("certbot._internal.eff.handle_subscription"):
                target = "certbot._internal.client.messages.ExternalAccountBinding.from_data"
                with mock.patch(target) as mock_eab_from_data:
                    self.config.eab_kid = None
                    self.config.eab_hmac_key = None
                    self._call()

                    self.assertIs(mock_eab_from_data.called, False)

    def test_external_account_required_without_eab_arguments(self):
        with self._patched_acme_client() as mock_client:
            mock_client().client.net.key.public_key = mock.Mock(side_effect=self._public_key_mock)
            mock_client().external_account_required.side_effect = self._true_mock
            with mock.patch("certbot._internal.eff.handle_subscription"):
                with mock.patch("certbot._internal.client.messages.ExternalAccountBinding.from_data"):
                    self.config.eab_kid = None
                    self.config.eab_hmac_key = None

                    self.assertRaises(errors.Error, self._call)

    def test_unsupported_error(self):
        from acme import messages
        msg = "Test"
        mx_err = messages.Error.with_code("malformed", detail=msg, title="title")
        with self._patched_acme_client() as mock_client:
            mock_client().client.directory.__getitem__ = mock.Mock(
                side_effect=self._new_acct_dir_mock
            )
            mock_client().external_account_required.side_effect = self._false_mock
            with mock.patch("certbot._internal.eff.handle_subscription") as mock_handle:
                mock_client().new_account.side_effect = [mx_err, mock.MagicMock()]
                self.assertRaises(messages.Error, self._call)
        self.assertIs(mock_handle.called, False)


class ClientTestCommon(test_util.ConfigTestCase):
    """Common base class for certbot._internal.client.Client tests."""

    def setUp(self):
        super().setUp()
        self.config.no_verify_ssl = False
        self.config.allow_subset_of_names = False

        self.account = mock.MagicMock(**{"key.pem": KEY})

        from certbot._internal.client import Client
        with mock.patch("certbot._internal.client.acme_client") as acme:
            self.acme_client = acme.ClientV2
            self.acme = self.acme_client.return_value = mock.MagicMock()
            self.client_network = acme.ClientNetwork
            self.client = Client(
                config=self.config, account_=self.account,
                auth=None, installer=None)


class ClientTest(ClientTestCommon):
    """Tests for certbot._internal.client.Client."""

    def setUp(self):
        super().setUp()

        self.config.allow_subset_of_names = False
        self.config.dry_run = False
        self.config.strict_permissions = True
        self.eg_domains = ["example.com", "www.example.com"]
        self.eg_order = mock.MagicMock(
            authorizations=[None],
            csr_pem=mock.sentinel.csr_pem)

    def test_init_acme_verify_ssl(self):
        self.assertIs(self.client_network.call_args[1]['verify_ssl'], True)

    def _mock_obtain_certificate(self):
        self.client.auth_handler = mock.MagicMock()
        self.client.auth_handler.handle_authorizations.return_value = [None]
        self.client.auth_handler.deactivate_valid_authorizations.return_value = ([], [])
        self.acme.finalize_order.return_value = self.eg_order
        self.acme.new_order.return_value = self.eg_order
        self.eg_order.update.return_value = self.eg_order

    def _check_obtain_certificate(self, auth_count=1):
        if auth_count == 1:
            self.client.auth_handler.handle_authorizations.assert_called_once_with(
                self.eg_order,
                self.config,
                self.config.allow_subset_of_names)
        else:
            self.assertEqual(self.client.auth_handler.handle_authorizations.call_count, auth_count)

        self.acme.finalize_order.assert_called_once_with(
            self.eg_order, mock.ANY,
            fetch_alternative_chains=self.config.preferred_chain is not None)

    @mock.patch("certbot._internal.client.crypto_util")
    @mock.patch("certbot._internal.client.logger")
    def test_obtain_certificate_from_csr(self, mock_logger, mock_crypto_util):
        self._mock_obtain_certificate()
        test_csr = util.CSR(form="pem", file=None, data=CSR_SAN)
        auth_handler = self.client.auth_handler
        self._set_mock_from_fullchain(mock_crypto_util.cert_and_chain_from_fullchain)

        orderr = self.acme.new_order(test_csr.data)
        auth_handler.handle_authorizations(orderr, self.config, False)
        self.assertEqual(
            (mock.sentinel.cert, mock.sentinel.chain),
            self.client.obtain_certificate_from_csr(
                test_csr,
                orderr=orderr))
        mock_crypto_util.find_chain_with_issuer.assert_not_called()
        # and that the cert was obtained correctly
        self._check_obtain_certificate()

        # Test that --preferred-chain results in chain selection
        self.config.preferred_chain = "some issuer"
        self.assertEqual(
            (mock.sentinel.cert, mock.sentinel.chain),
            self.client.obtain_certificate_from_csr(
                test_csr,
                orderr=orderr))
        mock_crypto_util.find_chain_with_issuer.assert_called_once_with(
            [orderr.fullchain_pem] + orderr.alternative_fullchains_pem,
            "some issuer", True)
        self.config.preferred_chain = None

        # Test for default issuance_timeout
        expected_deadline = \
            datetime.datetime.now() + datetime.timedelta(
                seconds=constants.CLI_DEFAULTS["issuance_timeout"])
        self.client.obtain_certificate_from_csr(test_csr, orderr=orderr)
        ((_, deadline), _) = self.client.acme.finalize_order.call_args
        self.assertTrue(
            abs(expected_deadline - deadline) <= datetime.timedelta(seconds=1))

        # Test for specific issuance_timeout (300 seconds)
        expected_deadline = \
            datetime.datetime.now() + datetime.timedelta(seconds=300)
        self.config.issuance_timeout = 300
        self.client.obtain_certificate_from_csr(test_csr, orderr=orderr)
        ((_, deadline), _) = self.client.acme.finalize_order.call_args
        self.assertTrue(
            abs(expected_deadline - deadline) <= datetime.timedelta(seconds=1))

        # Test for orderr=None
        self.assertEqual(
            (mock.sentinel.cert, mock.sentinel.chain),
            self.client.obtain_certificate_from_csr(
                test_csr,
                orderr=None))
        auth_handler.handle_authorizations.assert_called_with(self.eg_order, self.config, False)

        # Test for no auth_handler
        self.client.auth_handler = None
        self.assertRaises(
            errors.Error,
            self.client.obtain_certificate_from_csr,
            test_csr)
        mock_logger.error.assert_called_once_with(mock.ANY)

    @mock.patch("certbot._internal.client.crypto_util")
    def test_obtain_certificate(self, mock_crypto_util):
        csr = util.CSR(form="pem", file=None, data=CSR_SAN)
        mock_crypto_util.generate_csr.return_value = csr
        mock_crypto_util.generate_key.return_value = mock.sentinel.key
        self._set_mock_from_fullchain(mock_crypto_util.cert_and_chain_from_fullchain)

        self._test_obtain_certificate_common(mock.sentinel.key, csr)

        mock_crypto_util.generate_key.assert_called_once_with(
            key_size=self.config.rsa_key_size,
            key_dir=None,
            key_type=self.config.key_type,
            elliptic_curve="secp256r1",
            strict_permissions=True,
        )
        mock_crypto_util.generate_csr.assert_called_once_with(
            mock.sentinel.key, self.eg_domains, None, False, True)
        mock_crypto_util.cert_and_chain_from_fullchain.assert_called_once_with(
            self.eg_order.fullchain_pem)

    @mock.patch("certbot._internal.client.crypto_util")
    def test_obtain_certificate_partial_success(self, mock_crypto_util):
        csr = util.CSR(form="pem", file=mock.sentinel.csr_file, data=CSR_SAN)
        key = util.CSR(form="pem", file=mock.sentinel.key_file, data=CSR_SAN)
        mock_crypto_util.generate_csr.return_value = csr
        mock_crypto_util.generate_key.return_value = key
        self._set_mock_from_fullchain(mock_crypto_util.cert_and_chain_from_fullchain)

        authzr = self._authzr_from_domains(["example.com"])
        self.config.allow_subset_of_names = True
        self._test_obtain_certificate_common(key, csr, authzr_ret=authzr, auth_count=2)

        self.assertEqual(mock_crypto_util.generate_key.call_count, 2)
        self.assertEqual(mock_crypto_util.generate_csr.call_count, 2)
        self.assertEqual(mock_crypto_util.cert_and_chain_from_fullchain.call_count, 1)

    @mock.patch("certbot._internal.client.crypto_util")
    def test_obtain_certificate_finalize_order_partial_success(self, mock_crypto_util):
        from acme import messages
        csr = util.CSR(form="pem", file=mock.sentinel.csr_file, data=CSR_SAN)
        key = util.CSR(form="pem", file=mock.sentinel.key_file, data=CSR_SAN)
        mock_crypto_util.generate_csr.return_value = csr
        mock_crypto_util.generate_key.return_value = key
        self._set_mock_from_fullchain(mock_crypto_util.cert_and_chain_from_fullchain)

        self._mock_obtain_certificate()
        authzr = self._authzr_from_domains(self.eg_domains)
        self.eg_order.authorizations = authzr
        self.client.auth_handler.handle_authorizations.return_value = authzr

        identifier = messages.Identifier(typ=messages.IDENTIFIER_FQDN, value='example.com')
        subproblem = messages.Error.with_code('caa', detail='bar', title='title', identifier=identifier)
        error_with_subproblems = messages.Error.with_code('malformed', detail='foo', title='title', subproblems=[subproblem])
        self.client.acme.finalize_order.side_effect = [error_with_subproblems, mock.DEFAULT]

        self.config.allow_subset_of_names = True

        with test_util.patch_display_util():
            result = self.client.obtain_certificate(self.eg_domains)

        self.assertEqual(
            result,
            (mock.sentinel.cert, mock.sentinel.chain, key, csr))
        self.assertEqual(self.client.auth_handler.handle_authorizations.call_count, 2)
        self.assertEqual(self.acme.finalize_order.call_count, 2)

        successful_domains = [d for d in self.eg_domains if d != 'example.com']
        self.assertEqual(mock_crypto_util.generate_key.call_count, 2)
        mock_crypto_util.generate_csr.assert_has_calls([
            mock.call(key, self.eg_domains, None, self.config.must_staple, self.config.strict_permissions),
            mock.call(key, successful_domains, None, self.config.must_staple, self.config.strict_permissions)])
        self.assertEqual(mock_crypto_util.cert_and_chain_from_fullchain.call_count, 1)

    @mock.patch("certbot._internal.client.crypto_util")
    def test_obtain_certificate_finalize_order_no_retryable_domains(self, mock_crypto_util):
        from acme import messages
        csr = util.CSR(form="pem", file=mock.sentinel.csr_file, data=CSR_SAN)
        key = util.CSR(form="pem", file=mock.sentinel.key_file, data=CSR_SAN)
        mock_crypto_util.generate_csr.return_value = csr
        mock_crypto_util.generate_key.return_value = key
        self._set_mock_from_fullchain(mock_crypto_util.cert_and_chain_from_fullchain)

        self._mock_obtain_certificate()
        authzr = self._authzr_from_domains(self.eg_domains)
        self.eg_order.authorizations = authzr
        self.client.auth_handler.handle_authorizations.return_value = authzr

        identifier1 = messages.Identifier(typ=messages.IDENTIFIER_FQDN, value='example.com')
        identifier2 = messages.Identifier(typ=messages.IDENTIFIER_FQDN, value='www.example.com')
        subproblem1 = messages.Error.with_code('caa', detail='bar', title='title', identifier=identifier1)
        subproblem2 = messages.Error.with_code('caa', detail='bar', title='title', identifier=identifier2)
        error_with_subproblems = messages.Error.with_code('malformed', detail='foo', title='title', subproblems=[subproblem1, subproblem2])
        self.client.acme.finalize_order.side_effect = error_with_subproblems

        self.config.allow_subset_of_names = True

        self.assertRaises(messages.Error, self.client.obtain_certificate, self.eg_domains)
        self.assertEqual(self.client.auth_handler.handle_authorizations.call_count, 1)
        self.assertEqual(self.acme.finalize_order.call_count, 1)
        self.assertEqual(mock_crypto_util.generate_key.call_count, 1)
        self.assertEqual(mock_crypto_util.cert_and_chain_from_fullchain.call_count, 0)

    @mock.patch("certbot._internal.client.crypto_util")
    def test_obtain_certificate_finalize_order_rejected_identifier_no_subproblems(self, mock_crypto_util):
        from acme import messages
        csr = util.CSR(form="pem", file=mock.sentinel.csr_file, data=CSR_SAN)
        key = util.CSR(form="pem", file=mock.sentinel.key_file, data=CSR_SAN)
        mock_crypto_util.generate_csr.return_value = csr
        mock_crypto_util.generate_key.return_value = key
        self._set_mock_from_fullchain(mock_crypto_util.cert_and_chain_from_fullchain)

        self._mock_obtain_certificate()
        authzr = self._authzr_from_domains(self.eg_domains)
        self.eg_order.authorizations = authzr
        self.client.auth_handler.handle_authorizations.return_value = authzr

        error = messages.Error.with_code('caa', detail='foo', title='title')
        self.client.acme.finalize_order.side_effect = error

        self.config.allow_subset_of_names = True

        self.assertRaises(messages.Error, self.client.obtain_certificate,
                          self.eg_domains)
        self.assertEqual(self.client.auth_handler.handle_authorizations.call_count, 1)
        self.assertEqual(self.acme.finalize_order.call_count, 1)
        self.assertEqual(mock_crypto_util.generate_key.call_count, 1)
        self.assertEqual(mock_crypto_util.cert_and_chain_from_fullchain.call_count, 0)

    @mock.patch("certbot._internal.client.crypto_util")
    def test_obtain_certificate_get_order_partial_success(self, mock_crypto_util):
        from acme import messages
        csr = util.CSR(form="pem", file=mock.sentinel.csr_file, data=CSR_SAN)
        key = util.CSR(form="pem", file=mock.sentinel.key_file, data=CSR_SAN)
        mock_crypto_util.generate_csr.return_value = csr
        mock_crypto_util.generate_key.return_value = key
        self._set_mock_from_fullchain(mock_crypto_util.cert_and_chain_from_fullchain)

        self._mock_obtain_certificate()
        authzr = self._authzr_from_domains(self.eg_domains)
        self.eg_order.authorizations = authzr
        self.client.auth_handler.handle_authorizations.return_value = authzr

        identifier = messages.Identifier(typ=messages.IDENTIFIER_FQDN, value='example.com')
        subproblem = messages.Error.with_code('caa', detail='bar', title='title', identifier=identifier)
        error_with_subproblems = messages.Error.with_code('malformed', detail='foo', title='title', subproblems=[subproblem])
        self.client.acme.new_order.side_effect = [error_with_subproblems, mock.DEFAULT]

        self.config.allow_subset_of_names = True

        with test_util.patch_display_util():
            result = self.client.obtain_certificate(self.eg_domains)

        self.assertEqual(
            result,
            (mock.sentinel.cert, mock.sentinel.chain, key, csr))
        self.assertEqual(self.client.auth_handler.handle_authorizations.call_count, 1)
        self.assertEqual(self.acme.new_order.call_count, 2)

        successful_domains = [d for d in self.eg_domains if d != 'example.com']
        self.assertEqual(mock_crypto_util.generate_key.call_count, 2)
        mock_crypto_util.generate_csr.assert_has_calls([
            mock.call(key, self.eg_domains, None, self.config.must_staple, self.config.strict_permissions),
            mock.call(key, successful_domains, None, self.config.must_staple, self.config.strict_permissions)])
        self.assertEqual(mock_crypto_util.cert_and_chain_from_fullchain.call_count, 1)

    @mock.patch("certbot._internal.client.crypto_util")
    def test_obtain_certificate_get_order_no_retryable_domains(self, mock_crypto_util):
        from acme import messages
        csr = util.CSR(form="pem", file=mock.sentinel.csr_file, data=CSR_SAN)
        key = util.CSR(form="pem", file=mock.sentinel.key_file, data=CSR_SAN)
        mock_crypto_util.generate_csr.return_value = csr
        mock_crypto_util.generate_key.return_value = key
        self._set_mock_from_fullchain(mock_crypto_util.cert_and_chain_from_fullchain)

        self._mock_obtain_certificate()
        authzr = self._authzr_from_domains(self.eg_domains)
        self.eg_order.authorizations = authzr
        self.client.auth_handler.handle_authorizations.return_value = authzr

        identifier1 = messages.Identifier(typ=messages.IDENTIFIER_FQDN, value='example.com')
        identifier2 = messages.Identifier(typ=messages.IDENTIFIER_FQDN, value='www.example.com')
        subproblem1 = messages.Error.with_code('caa', detail='bar', title='title', identifier=identifier1)
        subproblem2 = messages.Error.with_code('caa', detail='bar', title='title', identifier=identifier2)
        error_with_subproblems = messages.Error.with_code('malformed', detail='foo', title='title', subproblems=[subproblem1, subproblem2])
        self.client.acme.new_order.side_effect = error_with_subproblems

        self.config.allow_subset_of_names = True

        self.assertRaises(messages.Error, self.client.obtain_certificate, self.eg_domains)
        self.assertEqual(self.client.auth_handler.handle_authorizations.call_count, 0)
        self.assertEqual(self.acme.new_order.call_count, 1)
        self.assertEqual(mock_crypto_util.generate_key.call_count, 1)
        self.assertEqual(mock_crypto_util.cert_and_chain_from_fullchain.call_count, 0)

    @mock.patch("certbot._internal.client.crypto_util")
    def test_obtain_certificate_get_order_rejected_identifier_no_subproblems(self, mock_crypto_util):
        from acme import messages
        csr = util.CSR(form="pem", file=mock.sentinel.csr_file, data=CSR_SAN)
        key = util.CSR(form="pem", file=mock.sentinel.key_file, data=CSR_SAN)
        mock_crypto_util.generate_csr.return_value = csr
        mock_crypto_util.generate_key.return_value = key
        self._set_mock_from_fullchain(mock_crypto_util.cert_and_chain_from_fullchain)

        self._mock_obtain_certificate()
        authzr = self._authzr_from_domains(self.eg_domains)
        self.eg_order.authorizations = authzr
        self.client.auth_handler.handle_authorizations.return_value = authzr

        error = messages.Error.with_code('caa', detail='foo', title='title')
        self.client.acme.new_order.side_effect = error

        self.config.allow_subset_of_names = True

        self.assertRaises(messages.Error, self.client.obtain_certificate, self.eg_domains)
        self.assertEqual(self.client.auth_handler.handle_authorizations.call_count, 0)
        self.assertEqual(self.acme.new_order.call_count, 1)
        self.assertEqual(mock_crypto_util.generate_key.call_count, 1)
        self.assertEqual(mock_crypto_util.cert_and_chain_from_fullchain.call_count, 0)

    @mock.patch("certbot._internal.client.crypto_util")
    @mock.patch("certbot._internal.client.acme_crypto_util")
    def test_obtain_certificate_dry_run(self, mock_acme_crypto, mock_crypto):
        csr = util.CSR(form="pem", file=None, data=CSR_SAN)
        mock_acme_crypto.make_csr.return_value = CSR_SAN
        mock_crypto.make_key.return_value = mock.sentinel.key_pem
        key = util.Key(file=None, pem=mock.sentinel.key_pem)
        self._set_mock_from_fullchain(mock_crypto.cert_and_chain_from_fullchain)

        self.client.config.dry_run = True
        self._test_obtain_certificate_common(key, csr)

        mock_crypto.make_key.assert_called_once_with(
            bits=self.config.rsa_key_size,
            elliptic_curve="secp256r1",
            key_type=self.config.key_type,
        )
        mock_acme_crypto.make_csr.assert_called_once_with(
            mock.sentinel.key_pem, self.eg_domains, self.config.must_staple)
        mock_crypto.generate_key.assert_not_called()
        mock_crypto.generate_csr.assert_not_called()
        self.assertEqual(mock_crypto.cert_and_chain_from_fullchain.call_count, 1)

    @mock.patch("certbot._internal.client.logger")
    @mock.patch("certbot._internal.client.crypto_util")
    @mock.patch("certbot._internal.client.acme_crypto_util")
    def test_obtain_certificate_dry_run_authz_deactivations_failed(self, mock_acme_crypto,
                                                                   mock_crypto, mock_log):
        from acme import messages
        csr = util.CSR(form="pem", file=None, data=CSR_SAN)
        mock_acme_crypto.make_csr.return_value = CSR_SAN
        mock_crypto.make_key.return_value = mock.sentinel.key_pem
        key = util.Key(file=None, pem=mock.sentinel.key_pem)
        self._set_mock_from_fullchain(mock_crypto.cert_and_chain_from_fullchain)

        self._mock_obtain_certificate()
        self.client.config.dry_run = True

        # Two authzs that are already valid and should get deactivated (dry run)
        authzrs = self._authzr_from_domains(["example.com", "www.example.com"])
        for authzr in authzrs:
            authzr.body.status = messages.STATUS_VALID

        # One deactivation succeeds, one fails
        auth_handler = self.client.auth_handler
        auth_handler.deactivate_valid_authorizations.return_value = ([authzrs[0]], [authzrs[1]])

        # Certificate should get issued despite one failed deactivation
        self.eg_order.authorizations = authzrs
        self.client.auth_handler.handle_authorizations.return_value = authzrs
        with test_util.patch_display_util():
            result = self.client.obtain_certificate(self.eg_domains)
        self.assertEqual(result, (mock.sentinel.cert, mock.sentinel.chain, key, csr))
        self._check_obtain_certificate(1)

        # Deactivation success/failure should have been handled properly
        self.assertEqual(auth_handler.deactivate_valid_authorizations.call_count, 1,
                        "Deactivate authorizations should be called")
        self.assertEqual(self.acme.new_order.call_count, 2,
                        "Order should be recreated due to successfully deactivated authorizations")
        mock_log.warning.assert_called_with("Certbot was unable to obtain fresh authorizations for"
                                            " every domain. The dry run will continue, but results"
                                            " may not be accurate.")

    def _set_mock_from_fullchain(self, mock_from_fullchain):
        mock_cert = mock.Mock()
        mock_cert.encode.return_value = mock.sentinel.cert
        mock_chain = mock.Mock()
        mock_chain.encode.return_value = mock.sentinel.chain
        mock_from_fullchain.return_value = (mock_cert, mock_chain)

    def _authzr_from_domains(self, domains):
        authzr = []

        # domain ordering should not be affected by authorization order
        for domain in reversed(domains):
            authzr.append(
                mock.MagicMock(
                    body=mock.MagicMock(
                        identifier=mock.MagicMock(
                            value=domain))))
        return authzr

    def _test_obtain_certificate_common(self, key, csr, authzr_ret=None, auth_count=1):
        self._mock_obtain_certificate()

        # return_value is essentially set to (None, None) in
        # _mock_obtain_certificate(), which breaks this test.
        # Thus fixed by the next line.
        authzr = authzr_ret or self._authzr_from_domains(self.eg_domains)

        self.eg_order.authorizations = authzr
        self.client.auth_handler.handle_authorizations.return_value = authzr

        with test_util.patch_display_util():
            result = self.client.obtain_certificate(self.eg_domains)

        self.assertEqual(
            result,
            (mock.sentinel.cert, mock.sentinel.chain, key, csr))
        self._check_obtain_certificate(auth_count)

    @mock.patch('certbot._internal.client.Client.obtain_certificate')
    @mock.patch('certbot._internal.storage.RenewableCert.new_lineage')
    def test_obtain_and_enroll_certificate(self,
                                           mock_storage, mock_obtain_certificate):
        domains = ["*.example.com", "example.com"]
        mock_obtain_certificate.return_value = (mock.MagicMock(),
                                                mock.MagicMock(), mock.MagicMock(), None)

        self.client.config.dry_run = False
        self.assertTrue(self.client.obtain_and_enroll_certificate(domains, "example_cert"))

        self.assertTrue(self.client.obtain_and_enroll_certificate(domains, None))
        self.assertTrue(self.client.obtain_and_enroll_certificate(domains[1:], None))

        self.client.config.dry_run = True

        self.assertFalse(self.client.obtain_and_enroll_certificate(domains, None))

        names = [call[0][0] for call in mock_storage.call_args_list]
        self.assertEqual(names, ["example_cert", "example.com", "example.com"])

    @mock.patch("certbot._internal.cli.helpful_parser")
    def test_save_certificate(self, mock_parser):
        certs = ["cert_512.pem", "cert-san_512.pem"]
        tmp_path = tempfile.mkdtemp()

        cert_pem = test_util.load_vector(certs[0])
        chain_pem = (test_util.load_vector(certs[0]) + test_util.load_vector(certs[1]))
        candidate_cert_path = os.path.join(tmp_path, "certs", "cert_512.pem")
        candidate_chain_path = os.path.join(tmp_path, "chains", "chain.pem")
        candidate_fullchain_path = os.path.join(tmp_path, "chains", "fullchain.pem")
        mock_parser.verb = "certonly"
        mock_parser.args = ["--cert-path", candidate_cert_path,
                            "--chain-path", candidate_chain_path,
                            "--fullchain-path", candidate_fullchain_path]

        cert_path, chain_path, fullchain_path = self.client.save_certificate(
            cert_pem, chain_pem, candidate_cert_path, candidate_chain_path,
            candidate_fullchain_path)

        self.assertEqual(os.path.dirname(cert_path),
                         os.path.dirname(candidate_cert_path))
        self.assertEqual(os.path.dirname(chain_path),
                         os.path.dirname(candidate_chain_path))
        self.assertEqual(os.path.dirname(fullchain_path),
                         os.path.dirname(candidate_fullchain_path))

        with open(cert_path, "rb") as cert_file:
            cert_contents = cert_file.read()
        self.assertEqual(cert_contents, test_util.load_vector(certs[0]))

        with open(chain_path, "rb") as chain_file:
            chain_contents = chain_file.read()
        self.assertEqual(chain_contents, test_util.load_vector(certs[0]) +
                         test_util.load_vector(certs[1]))

        shutil.rmtree(tmp_path)

    @test_util.patch_display_util()
    def test_deploy_certificate_success(self, mock_util):
        self.assertRaises(errors.Error, self.client.deploy_certificate,
                          ["foo.bar"], "key", "cert", "chain", "fullchain")

        installer = mock.MagicMock()
        self.client.installer = installer

        self.client.deploy_certificate(["foo.bar"], "key", "cert", "chain", "fullchain")
        installer.deploy_cert.assert_called_once_with(
            cert_path=os.path.abspath("cert"),
            chain_path=os.path.abspath("chain"),
            domain='foo.bar',
            fullchain_path='fullchain',
            key_path=os.path.abspath("key"))
        self.assertEqual(installer.save.call_count, 2)
        installer.restart.assert_called_once_with()

    @mock.patch('certbot._internal.client.display_util.notify')
    @test_util.patch_display_util()
    def test_deploy_certificate_failure(self, mock_util, mock_notify):
        installer = mock.MagicMock()
        self.client.installer = installer
        self.config.installer = "foobar"

        installer.deploy_cert.side_effect = errors.PluginError
        self.assertRaises(errors.PluginError, self.client.deploy_certificate,
                          ["foo.bar"], "key", "cert", "chain", "fullchain")
        installer.recovery_routine.assert_called_once_with()

        mock_notify.assert_any_call('Deploying certificate')


    @test_util.patch_display_util()
    def test_deploy_certificate_save_failure(self, mock_util):
        installer = mock.MagicMock()
        self.client.installer = installer

        installer.save.side_effect = errors.PluginError
        self.assertRaises(errors.PluginError, self.client.deploy_certificate,
                          ["foo.bar"], "key", "cert", "chain", "fullchain")
        installer.recovery_routine.assert_called_once_with()

    @mock.patch('certbot._internal.client.display_util.notify')
    @test_util.patch_display_util()
    def test_deploy_certificate_restart_failure(self, mock_get_utility, mock_notify):
        installer = mock.MagicMock()
        installer.restart.side_effect = [errors.PluginError, None]
        self.client.installer = installer

        self.assertRaises(errors.PluginError, self.client.deploy_certificate,
                          ["foo.bar"], "key", "cert", "chain", "fullchain")
        mock_notify.assert_called_with(
            'We were unable to install your certificate, however, we successfully restored '
            'your server to its prior configuration.')
        installer.rollback_checkpoints.assert_called_once_with()
        self.assertEqual(installer.restart.call_count, 2)

    @mock.patch('certbot._internal.client.logger')
    @test_util.patch_display_util()
    def test_deploy_certificate_restart_failure2(self, mock_get_utility, mock_logger):
        installer = mock.MagicMock()
        installer.restart.side_effect = errors.PluginError
        installer.rollback_checkpoints.side_effect = errors.ReverterError
        self.client.installer = installer

        self.assertRaises(errors.PluginError, self.client.deploy_certificate,
                          ["foo.bar"], "key", "cert", "chain", "fullchain")
        self.assertEqual(mock_logger.error.call_count, 1)
        self.assertIn(
            'An error occurred and we failed to restore your config',
            mock_logger.error.call_args[0][0])
        installer.rollback_checkpoints.assert_called_once_with()
        self.assertEqual(installer.restart.call_count, 1)


class EnhanceConfigTest(ClientTestCommon):
    """Tests for certbot._internal.client.Client.enhance_config."""

    def setUp(self):
        super().setUp()

        self.config.hsts = False
        self.config.redirect = False
        self.config.staple = False
        self.config.uir = False
        self.domain = "example.org"

    def test_no_installer(self):
        self.assertRaises(
            errors.Error, self.client.enhance_config, [self.domain], None)

    def test_unsupported(self):
        self.client.installer = mock.MagicMock()
        self.client.installer.supported_enhancements.return_value = []

        self.config.redirect = None
        self.config.hsts = True
        with mock.patch("certbot._internal.client.logger") as mock_logger:
            self.client.enhance_config([self.domain], None)
        self.assertEqual(mock_logger.error.call_count, 1)
        self.client.installer.enhance.assert_not_called()

    @mock.patch("certbot._internal.client.logger")
    def test_already_exists_header(self, mock_log):
        self.config.hsts = True
        self._test_with_already_existing()
        self.assertIs(mock_log.info.called, True)
        self.assertEqual(mock_log.info.call_args[0][1],
                          'Strict-Transport-Security')

    @mock.patch("certbot._internal.client.logger")
    def test_already_exists_redirect(self, mock_log):
        self.config.redirect = True
        self._test_with_already_existing()
        self.assertIs(mock_log.info.called, True)
        self.assertEqual(mock_log.info.call_args[0][1],
                          'redirect')

    @mock.patch("certbot._internal.client.logger")
    def test_config_set_no_warning_redirect(self, mock_log):
        self.config.redirect = False
        self._test_with_already_existing()
        self.assertIs(mock_log.warning.called, False)

    @mock.patch("certbot._internal.client.logger")
    def test_no_warn_redirect(self, mock_log):
        self.config.redirect = None
        self._test_with_all_supported()
        self.assertIs(mock_log.warning.called, False)

    def test_no_ask_hsts(self):
        self.config.hsts = True
        self._test_with_all_supported()
        self.client.installer.enhance.assert_called_with(
            self.domain, "ensure-http-header", "Strict-Transport-Security")

    def test_no_ask_redirect(self):
        self.config.redirect = True
        self._test_with_all_supported()
        self.client.installer.enhance.assert_called_with(
            self.domain, "redirect", None)

    def test_no_ask_staple(self):
        self.config.staple = True
        self._test_with_all_supported()
        self.client.installer.enhance.assert_called_with(
            self.domain, "staple-ocsp", None)

    def test_no_ask_uir(self):
        self.config.uir = True
        self._test_with_all_supported()
        self.client.installer.enhance.assert_called_with(
            self.domain, "ensure-http-header", "Upgrade-Insecure-Requests")

    def test_enhance_failure(self):
        self.client.installer = mock.MagicMock()
        self.client.installer.enhance.side_effect = errors.PluginError
        self._test_error(enhance_error=True)
        self.client.installer.recovery_routine.assert_called_once_with()

    def test_save_failure(self):
        self.client.installer = mock.MagicMock()
        self.client.installer.save.side_effect = errors.PluginError
        self._test_error()
        self.client.installer.recovery_routine.assert_called_once_with()
        self.client.installer.save.assert_called_once_with(mock.ANY)

    def test_restart_failure(self):
        self.client.installer = mock.MagicMock()
        self.client.installer.restart.side_effect = [errors.PluginError, None]
        self._test_error_with_rollback()

    def test_restart_failure2(self):
        installer = mock.MagicMock()
        installer.restart.side_effect = errors.PluginError
        installer.rollback_checkpoints.side_effect = errors.ReverterError
        self.client.installer = installer
        self._test_error_with_rollback()

    def _test_error_with_rollback(self):
        self._test_error()
        self.assertIs(self.client.installer.restart.called, True)

    def _test_error(self, enhance_error=False, restart_error=False):
        self.config.redirect = True
        with mock.patch('certbot._internal.client.logger') as mock_logger, \
             test_util.patch_display_util() as mock_gu:
            self.assertRaises(
                errors.PluginError, self._test_with_all_supported)

        if enhance_error:
            self.assertEqual(mock_logger.error.call_count, 1)
            self.assertEqual('Unable to set the %s enhancement for %s.', mock_logger.error.call_args_list[0][0][0])
        if restart_error:
            mock_logger.critical.assert_called_with(
                'Rolling back to previous server configuration...')

    def _test_with_all_supported(self):
        if self.client.installer is None:
            self.client.installer = mock.MagicMock()
        self.client.installer.supported_enhancements.return_value = [
            "ensure-http-header", "redirect", "staple-ocsp"]
        self.client.enhance_config([self.domain], None)
        self.assertEqual(self.client.installer.save.call_count, 1)
        self.assertEqual(self.client.installer.restart.call_count, 1)

    def _test_with_already_existing(self):
        self.client.installer = mock.MagicMock()
        self.client.installer.supported_enhancements.return_value = [
            "ensure-http-header", "redirect", "staple-ocsp"]
        self.client.installer.enhance.side_effect = errors.PluginEnhancementAlreadyPresent()
        self.client.enhance_config([self.domain], None)


class RollbackTest(unittest.TestCase):
    """Tests for certbot._internal.client.rollback."""

    def setUp(self):
        self.m_install = mock.MagicMock()

    @classmethod
    def _call(cls, checkpoints, side_effect):
        from certbot._internal.client import rollback
        with mock.patch("certbot._internal.client.plugin_selection.pick_installer") as mpi:
            mpi.side_effect = side_effect
            rollback(None, checkpoints, {}, mock.MagicMock())

    def test_no_problems(self):
        self._call(1, self.m_install)
        self.assertEqual(self.m_install().rollback_checkpoints.call_count, 1)
        self.assertEqual(self.m_install().restart.call_count, 1)

    def test_no_installer(self):
        self._call(1, None)  # Just make sure no exceptions are raised


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
