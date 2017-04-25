"""Tests for certbot.client."""
import os
import shutil
import tempfile
import unittest

import OpenSSL
import mock

from acme import errors as acme_errors
from acme import jose

from certbot import account
from certbot import errors
from certbot import util

import certbot.tests.util as test_util


KEY = test_util.load_vector("rsa512_key.pem")
CSR_SAN = test_util.load_vector("csr-san.pem")


class ConfigHelper(object):
    """Creates a dummy object to imitate a namespace object

        Example: cfg = ConfigHelper(redirect=True, hsts=False, uir=False)
        will result in: cfg.redirect=True, cfg.hsts=False, etc.
    """
    def __init__(self, **kwds):
        self.__dict__.update(kwds)

class RegisterTest(unittest.TestCase):
    """Tests for certbot.client.register."""

    def setUp(self):
        self.config = mock.MagicMock(rsa_key_size=1024, register_unsafely_without_email=False)
        self.account_storage = account.AccountMemoryStorage()
        self.tos_cb = mock.MagicMock()

    def _call(self):
        from certbot.client import register
        return register(self.config, self.account_storage, self.tos_cb)

    def test_no_tos(self):
        with mock.patch("certbot.client.acme_client.Client") as mock_client:
            mock_client.register().terms_of_service = "http://tos"
            with mock.patch("certbot.eff.handle_subscription") as mock_handle:
                with mock.patch("certbot.account.report_new_account"):
                    self.tos_cb.return_value = False
                    self.assertRaises(errors.Error, self._call)
                    self.assertFalse(mock_handle.called)

                    self.tos_cb.return_value = True
                    self._call()
                    self.assertTrue(mock_handle.called)

                    self.tos_cb = None
                    self._call()
                    self.assertEqual(mock_handle.call_count, 2)

    def test_it(self):
        with mock.patch("certbot.client.acme_client.Client"):
            with mock.patch("certbot.account.report_new_account"):
                with mock.patch("certbot.eff.handle_subscription"):
                    self._call()

    @mock.patch("certbot.account.report_new_account")
    @mock.patch("certbot.client.display_ops.get_email")
    def test_email_retry(self, _rep, mock_get_email):
        from acme import messages
        self.config.noninteractive_mode = False
        msg = "DNS problem: NXDOMAIN looking up MX for example.com"
        mx_err = messages.Error.with_code('invalidContact', detail=msg)
        with mock.patch("certbot.client.acme_client.Client") as mock_client:
            with mock.patch("certbot.eff.handle_subscription") as mock_handle:
                mock_client().register.side_effect = [mx_err, mock.MagicMock()]
                self._call()
                self.assertEqual(mock_get_email.call_count, 1)
                self.assertTrue(mock_handle.called)

    @mock.patch("certbot.account.report_new_account")
    def test_email_invalid_noninteractive(self, _rep):
        from acme import messages
        msg = "DNS problem: NXDOMAIN looking up MX for example.com"
        mx_err = messages.Error.with_code('invalidContact', detail=msg)
        with mock.patch("certbot.client.acme_client.Client") as mock_client:
            with mock.patch("certbot.eff.handle_subscription"):
                mock_client().register.side_effect = [mx_err, mock.MagicMock()]
                self.assertRaises(errors.Error, self._call)

    def test_needs_email(self):
        self.config.email = None
        self.assertRaises(errors.Error, self._call)

    @mock.patch("certbot.client.logger")
    def test_without_email(self, mock_logger):
        with mock.patch("certbot.eff.handle_subscription") as mock_handle:
            with mock.patch("certbot.client.acme_client.Client"):
                with mock.patch("certbot.account.report_new_account"):
                    self.config.email = None
                    self.config.register_unsafely_without_email = True
                    self.config.dry_run = False
                    self._call()
                    mock_logger.info.assert_called_once_with(mock.ANY)
                    self.assertTrue(mock_handle.called)

    def test_unsupported_error(self):
        from acme import messages
        msg = "Test"
        mx_err = messages.Error(detail=msg, typ="malformed", title="title")
        with mock.patch("certbot.client.acme_client.Client") as mock_client:
            with mock.patch("certbot.eff.handle_subscription") as mock_handle:
                mock_client().register.side_effect = [mx_err, mock.MagicMock()]
                self.assertRaises(messages.Error, self._call)
        self.assertFalse(mock_handle.called)


class ClientTestCommon(unittest.TestCase):
    """Common base class for certbot.client.Client tests."""
    def setUp(self):
        self.config = mock.MagicMock(
            no_verify_ssl=False,
            config_dir="/etc/letsencrypt",
            work_dir="/var/lib/letsencrypt",
            allow_subset_of_names=False)

        # pylint: disable=star-args
        self.account = mock.MagicMock(**{"key.pem": KEY})

        from certbot.client import Client
        with mock.patch("certbot.client.acme_client.Client") as acme:
            self.acme_client = acme
            self.acme = acme.return_value = mock.MagicMock()
            self.client = Client(
                config=self.config, account_=self.account,
                auth=None, installer=None)


class ClientTest(ClientTestCommon):
    """Tests for certbot.client.Client."""
    def setUp(self):
        super(ClientTest, self).setUp()

        self.config.allow_subset_of_names = False
        self.config.config_dir = "/etc/letsencrypt"
        self.eg_domains = ["example.com", "www.example.com"]

    def test_init_acme_verify_ssl(self):
        net = self.acme_client.call_args[1]["net"]
        self.assertTrue(net.verify_ssl)

    def _mock_obtain_certificate(self):
        self.client.auth_handler = mock.MagicMock()
        self.client.auth_handler.get_authorizations.return_value = [None]
        self.acme.request_issuance.return_value = mock.sentinel.certr
        self.acme.fetch_chain.return_value = mock.sentinel.chain

    def _check_obtain_certificate(self):
        self.client.auth_handler.get_authorizations.assert_called_once_with(
            self.eg_domains,
            self.config.allow_subset_of_names)

        authzr = self.client.auth_handler.get_authorizations()

        self.acme.request_issuance.assert_called_once_with(
            jose.ComparableX509(OpenSSL.crypto.load_certificate_request(
                OpenSSL.crypto.FILETYPE_PEM, CSR_SAN)),
            authzr)

        self.acme.fetch_chain.assert_called_once_with(mock.sentinel.certr)

    @mock.patch("certbot.client.logger")
    @test_util.patch_get_utility()
    def test_obtain_certificate_from_csr(self, unused_mock_get_utility,
                                         mock_logger):
        self._mock_obtain_certificate()
        test_csr = util.CSR(form="pem", file=None, data=CSR_SAN)
        auth_handler = self.client.auth_handler

        authzr = auth_handler.get_authorizations(self.eg_domains, False)
        self.assertEqual(
            (mock.sentinel.certr, mock.sentinel.chain),
            self.client.obtain_certificate_from_csr(
                self.eg_domains,
                test_csr,
                authzr=authzr))
        # and that the cert was obtained correctly
        self._check_obtain_certificate()

        # Test for authzr=None
        self.assertEqual(
            (mock.sentinel.certr, mock.sentinel.chain),
            self.client.obtain_certificate_from_csr(
                self.eg_domains,
                test_csr,
                authzr=None))
        auth_handler.get_authorizations.assert_called_with(self.eg_domains)

        # Test for no auth_handler
        self.client.auth_handler = None
        self.assertRaises(
            errors.Error,
            self.client.obtain_certificate_from_csr,
            self.eg_domains,
            test_csr)
        mock_logger.warning.assert_called_once_with(mock.ANY)

    @test_util.patch_get_utility()
    def test_obtain_certificate_from_csr_retry_succeeded(
            self, mock_get_utility):
        self._mock_obtain_certificate()
        self.acme.fetch_chain.side_effect = [acme_errors.Error,
                                             mock.sentinel.chain]
        test_csr = util.CSR(form="der", file=None, data=CSR_SAN)
        auth_handler = self.client.auth_handler

        authzr = auth_handler.get_authorizations(self.eg_domains, False)
        self.assertEqual(
            (mock.sentinel.certr, mock.sentinel.chain),
            self.client.obtain_certificate_from_csr(
                self.eg_domains,
                test_csr,
                authzr=authzr))
        self.assertEqual(1, mock_get_utility().notification.call_count)

    @test_util.patch_get_utility()
    def test_obtain_certificate_from_csr_retry_failed(self, mock_get_utility):
        self._mock_obtain_certificate()
        self.acme.fetch_chain.side_effect = acme_errors.Error
        test_csr = util.CSR(form="der", file=None, data=CSR_SAN)
        auth_handler = self.client.auth_handler

        authzr = auth_handler.get_authorizations(self.eg_domains, False)
        self.assertRaises(
            acme_errors.Error,
            self.client.obtain_certificate_from_csr,
            self.eg_domains,
            test_csr,
            authzr=authzr)
        self.assertEqual(1, mock_get_utility().notification.call_count)

    @mock.patch("certbot.client.crypto_util")
    @test_util.patch_get_utility()
    def test_obtain_certificate(self, unused_mock_get_utility,
                                mock_crypto_util):
        self._mock_obtain_certificate()

        csr = util.CSR(form="pem", file=None, data=CSR_SAN)
        mock_crypto_util.init_save_csr.return_value = csr
        mock_crypto_util.init_save_key.return_value = mock.sentinel.key
        domains = ["example.com", "www.example.com"]

        # return_value is essentially set to (None, None) in
        # _mock_obtain_certificate(), which breaks this test.
        # Thus fixed by the next line.

        authzr = []

        # domain ordering should not be affected by authorization order
        for domain in reversed(domains):
            authzr.append(
                mock.MagicMock(
                    body=mock.MagicMock(
                        identifier=mock.MagicMock(
                            value=domain))))

        self.client.auth_handler.get_authorizations.return_value = authzr

        self.assertEqual(
            self.client.obtain_certificate(domains),
            (mock.sentinel.certr, mock.sentinel.chain, mock.sentinel.key, csr))

        mock_crypto_util.init_save_key.assert_called_once_with(
            self.config.rsa_key_size, self.config.key_dir)
        mock_crypto_util.init_save_csr.assert_called_once_with(
            mock.sentinel.key, domains, self.config.csr_dir)
        self._check_obtain_certificate()

    @mock.patch('certbot.client.Client.obtain_certificate')
    @mock.patch('certbot.storage.RenewableCert.new_lineage')
    @mock.patch('OpenSSL.crypto.dump_certificate')
    def test_obtain_and_enroll_certificate(self, mock_dump_certificate,
        mock_storage, mock_obtain_certificate):
        domains = ["example.com", "www.example.com"]
        mock_obtain_certificate.return_value = (mock.MagicMock(),
            mock.MagicMock(), mock.MagicMock(), None)

        self.client.config.dry_run = False
        self.assertTrue(self.client.obtain_and_enroll_certificate(domains, "example_cert"))

        self.assertTrue(self.client.obtain_and_enroll_certificate(domains, None))

        self.client.config.dry_run = True

        self.assertFalse(self.client.obtain_and_enroll_certificate(domains, None))

        self.assertTrue(mock_storage.call_count == 2)
        self.assertTrue(mock_dump_certificate.call_count == 2)

    @mock.patch("certbot.cli.helpful_parser")
    def test_save_certificate(self, mock_parser):
        # pylint: disable=too-many-locals
        certs = ["matching_cert.pem", "cert.pem", "cert-san.pem"]
        tmp_path = tempfile.mkdtemp()
        os.chmod(tmp_path, 0o755)  # TODO: really??

        certr = mock.MagicMock(body=test_util.load_comparable_cert(certs[0]))
        chain_cert = [test_util.load_comparable_cert(certs[1]),
                      test_util.load_comparable_cert(certs[2])]
        candidate_cert_path = os.path.join(tmp_path, "certs", "cert.pem")
        candidate_chain_path = os.path.join(tmp_path, "chains", "chain.pem")
        candidate_fullchain_path = os.path.join(tmp_path, "chains", "fullchain.pem")
        mock_parser.verb = "certonly"
        mock_parser.args = ["--cert-path", candidate_cert_path,
                "--chain-path", candidate_chain_path,
                "--fullchain-path", candidate_fullchain_path]

        cert_path, chain_path, fullchain_path = self.client.save_certificate(
            certr, chain_cert, candidate_cert_path, candidate_chain_path,
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
        self.assertEqual(chain_contents, test_util.load_vector(certs[1]) +
                         test_util.load_vector(certs[2]))

        shutil.rmtree(tmp_path)

    def test_deploy_certificate_success(self):
        self.assertRaises(errors.Error, self.client.deploy_certificate,
                          ["foo.bar"], "key", "cert", "chain", "fullchain")

        installer = mock.MagicMock()
        self.client.installer = installer

        self.client.deploy_certificate(
            ["foo.bar"], "key", "cert", "chain", "fullchain")
        installer.deploy_cert.assert_called_once_with(
            cert_path=os.path.abspath("cert"),
            chain_path=os.path.abspath("chain"),
            domain='foo.bar',
            fullchain_path='fullchain',
            key_path=os.path.abspath("key"))
        self.assertEqual(installer.save.call_count, 2)
        installer.restart.assert_called_once_with()

    def test_deploy_certificate_failure(self):
        installer = mock.MagicMock()
        self.client.installer = installer

        installer.deploy_cert.side_effect = errors.PluginError
        self.assertRaises(errors.PluginError, self.client.deploy_certificate,
                          ["foo.bar"], "key", "cert", "chain", "fullchain")
        installer.recovery_routine.assert_called_once_with()

    def test_deploy_certificate_save_failure(self):
        installer = mock.MagicMock()
        self.client.installer = installer

        installer.save.side_effect = errors.PluginError
        self.assertRaises(errors.PluginError, self.client.deploy_certificate,
                          ["foo.bar"], "key", "cert", "chain", "fullchain")
        installer.recovery_routine.assert_called_once_with()

    @test_util.patch_get_utility()
    def test_deploy_certificate_restart_failure(self, mock_get_utility):
        installer = mock.MagicMock()
        installer.restart.side_effect = [errors.PluginError, None]
        self.client.installer = installer

        self.assertRaises(errors.PluginError, self.client.deploy_certificate,
                          ["foo.bar"], "key", "cert", "chain", "fullchain")
        self.assertEqual(mock_get_utility().add_message.call_count, 1)
        installer.rollback_checkpoints.assert_called_once_with()
        self.assertEqual(installer.restart.call_count, 2)

    @test_util.patch_get_utility()
    def test_deploy_certificate_restart_failure2(self, mock_get_utility):
        installer = mock.MagicMock()
        installer.restart.side_effect = errors.PluginError
        installer.rollback_checkpoints.side_effect = errors.ReverterError
        self.client.installer = installer

        self.assertRaises(errors.PluginError, self.client.deploy_certificate,
                          ["foo.bar"], "key", "cert", "chain", "fullchain")
        self.assertEqual(mock_get_utility().add_message.call_count, 1)
        installer.rollback_checkpoints.assert_called_once_with()
        self.assertEqual(installer.restart.call_count, 1)


class EnhanceConfigTest(ClientTestCommon):
    """Tests for certbot.client.Client.enhance_config."""
    def setUp(self):
        super(EnhanceConfigTest, self).setUp()

        self.config.hsts = False
        self.config.redirect = False
        self.config.staple = False
        self.config.uir = False
        self.domain = "example.org"

    def test_no_installer(self):
        self.assertRaises(
            errors.Error, self.client.enhance_config, [self.domain], None)

    @mock.patch("certbot.client.enhancements")
    def test_unsupported(self, mock_enhancements):
        self.client.installer = mock.MagicMock()
        self.client.installer.supported_enhancements.return_value = []

        self.config.redirect = None
        self.config.hsts = True
        with mock.patch("certbot.client.logger") as mock_logger:
            self.client.enhance_config([self.domain], None)
        self.assertEqual(mock_logger.warning.call_count, 1)
        self.client.installer.enhance.assert_not_called()
        mock_enhancements.ask.assert_not_called()

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
        self._test_error()
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

    @mock.patch("certbot.client.enhancements.ask")
    def test_ask(self, mock_ask):
        self.config.redirect = None
        mock_ask.return_value = True
        self._test_with_all_supported()

    def _test_error_with_rollback(self):
        self._test_error()
        self.assertTrue(self.client.installer.restart.called)

    def _test_error(self):
        self.config.redirect = True
        with test_util.patch_get_utility() as mock_gu:
            self.assertRaises(
                errors.PluginError, self._test_with_all_supported)
        self.assertEqual(mock_gu().add_message.call_count, 1)

    def _test_with_all_supported(self):
        if self.client.installer is None:
            self.client.installer = mock.MagicMock()
        self.client.installer.supported_enhancements.return_value = [
            "ensure-http-header", "redirect", "staple-ocsp"]
        self.client.enhance_config([self.domain], None)
        self.assertEqual(self.client.installer.save.call_count, 1)
        self.assertEqual(self.client.installer.restart.call_count, 1)


class RollbackTest(unittest.TestCase):
    """Tests for certbot.client.rollback."""

    def setUp(self):
        self.m_install = mock.MagicMock()

    @classmethod
    def _call(cls, checkpoints, side_effect):
        from certbot.client import rollback
        with mock.patch("certbot.client.plugin_selection.pick_installer") as mpi:
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
