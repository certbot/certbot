"""Tests for letsencrypt.client."""
import os
import shutil
import tempfile
import unittest

import OpenSSL
import mock

from acme import jose

from letsencrypt import account
from letsencrypt import errors
from letsencrypt import le_util

from letsencrypt.tests import test_util


KEY = test_util.load_vector("rsa512_key.pem")
CSR_SAN = test_util.load_vector("csr-san.der")


class ConfigHelper(object):
    """Creates a dummy object to imitate a namespace object

        Example: cfg = ConfigHelper(redirect=True, hsts=False, uir=False)
        will result in: cfg.redirect=True, cfg.hsts=False, etc.
    """
    def __init__(self, **kwds):
        self.__dict__.update(kwds)

class RegisterTest(unittest.TestCase):
    """Tests for letsencrypt.client.register."""

    def setUp(self):
        self.config = mock.MagicMock(rsa_key_size=1024, register_unsafely_without_email=False)
        self.account_storage = account.AccountMemoryStorage()
        self.tos_cb = mock.MagicMock()

    def _call(self):
        from letsencrypt.client import register
        return register(self.config, self.account_storage, self.tos_cb)

    def test_no_tos(self):
        with mock.patch("letsencrypt.client.acme_client.Client") as mock_client:
            mock_client.register().terms_of_service = "http://tos"
            with mock.patch("letsencrypt.account.report_new_account"):
                self.tos_cb.return_value = False
                self.assertRaises(errors.Error, self._call)

                self.tos_cb.return_value = True
                self._call()

                self.tos_cb = None
                self._call()

    def test_it(self):
        with mock.patch("letsencrypt.client.acme_client.Client"):
            with mock.patch("letsencrypt.account.report_new_account"):
                self._call()

    @mock.patch("letsencrypt.account.report_new_account")
    @mock.patch("letsencrypt.client.display_ops.get_email")
    def test_email_retry(self, _rep, mock_get_email):
        from acme import messages
        msg = "Validation of contact mailto:sousaphone@improbablylongggstring.tld failed"
        mx_err = messages.Error(detail=msg, typ="malformed", title="title")
        with mock.patch("letsencrypt.client.acme_client.Client") as mock_client:
            mock_client().register.side_effect = [mx_err, mock.MagicMock()]
            self._call()
            self.assertEqual(mock_get_email.call_count, 1)

    def test_needs_email(self):
        self.config.email = None
        self.assertRaises(errors.Error, self._call)

class ClientTest(unittest.TestCase):
    """Tests for letsencrypt.client.Client."""

    def setUp(self):
        self.config = mock.MagicMock(
            no_verify_ssl=False, config_dir="/etc/letsencrypt")
        # pylint: disable=star-args
        self.account = mock.MagicMock(**{"key.pem": KEY})

        from letsencrypt.client import Client
        with mock.patch("letsencrypt.client.acme_client.Client") as acme:
            self.acme_client = acme
            self.acme = acme.return_value = mock.MagicMock()
            self.client = Client(
                config=self.config, account_=self.account,
                dv_auth=None, installer=None)

    def test_init_acme_verify_ssl(self):
        net = self.acme_client.call_args[1]["net"]
        self.assertTrue(net.verify_ssl)

    def _mock_obtain_certificate(self):
        self.client.auth_handler = mock.MagicMock()
        self.acme.request_issuance.return_value = mock.sentinel.certr
        self.acme.fetch_chain.return_value = mock.sentinel.chain

    def _check_obtain_certificate(self):
        self.client.auth_handler.get_authorizations.assert_called_once_with(
            ["example.com", "www.example.com"])
        self.acme.request_issuance.assert_called_once_with(
            jose.ComparableX509(OpenSSL.crypto.load_certificate_request(
                OpenSSL.crypto.FILETYPE_ASN1, CSR_SAN)),
            self.client.auth_handler.get_authorizations())
        self.acme.fetch_chain.assert_called_once_with(mock.sentinel.certr)

    def test_obtain_certificate_from_csr(self):
        self._mock_obtain_certificate()
        self.assertEqual(
            (mock.sentinel.certr, mock.sentinel.chain),
            self.client.obtain_certificate_from_csr(le_util.CSR(
                form="der", file=None, data=CSR_SAN)))
        self._check_obtain_certificate()

    @mock.patch("letsencrypt.client.crypto_util")
    def test_obtain_certificate(self, mock_crypto_util):
        self._mock_obtain_certificate()

        csr = le_util.CSR(form="der", file=None, data=CSR_SAN)
        mock_crypto_util.init_save_csr.return_value = csr
        mock_crypto_util.init_save_key.return_value = mock.sentinel.key
        domains = ["example.com", "www.example.com"]

        self.assertEqual(
            self.client.obtain_certificate(domains),
            (mock.sentinel.certr, mock.sentinel.chain, mock.sentinel.key, csr))

        mock_crypto_util.init_save_key.assert_called_once_with(
            self.config.rsa_key_size, self.config.key_dir)
        mock_crypto_util.init_save_csr.assert_called_once_with(
            mock.sentinel.key, domains, self.config.csr_dir)
        self._check_obtain_certificate()

    def test_save_certificate(self):
        certs = ["matching_cert.pem", "cert.pem", "cert-san.pem"]
        tmp_path = tempfile.mkdtemp()
        os.chmod(tmp_path, 0o755)  # TODO: really??

        certr = mock.MagicMock(body=test_util.load_cert(certs[0]))
        chain_cert = [test_util.load_cert(certs[1]),
                      test_util.load_cert(certs[2])]
        candidate_cert_path = os.path.join(tmp_path, "certs", "cert.pem")
        candidate_chain_path = os.path.join(tmp_path, "chains", "chain.pem")
        candidate_fullchain_path = os.path.join(tmp_path, "chains", "fullchain.pem")

        cert_path, chain_path, fullchain_path = self.client.save_certificate(
            certr, chain_cert, candidate_cert_path, candidate_chain_path,
            candidate_fullchain_path)

        self.assertEqual(os.path.dirname(cert_path),
                         os.path.dirname(candidate_cert_path))
        self.assertEqual(os.path.dirname(chain_path),
                         os.path.dirname(candidate_chain_path))
        self.assertEqual(os.path.dirname(fullchain_path),
                         os.path.dirname(candidate_fullchain_path))

        with open(cert_path, "r") as cert_file:
            cert_contents = cert_file.read()
        self.assertEqual(cert_contents, test_util.load_vector(certs[0]))

        with open(chain_path, "r") as chain_file:
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

    @mock.patch("letsencrypt.client.zope.component.getUtility")
    def test_deploy_certificate_restart_failure(self, mock_get_utility):
        installer = mock.MagicMock()
        installer.restart.side_effect = [errors.PluginError, None]
        self.client.installer = installer

        self.assertRaises(errors.PluginError, self.client.deploy_certificate,
                          ["foo.bar"], "key", "cert", "chain", "fullchain")
        self.assertEqual(mock_get_utility().add_message.call_count, 1)
        installer.rollback_checkpoints.assert_called_once_with()
        self.assertEqual(installer.restart.call_count, 2)

    @mock.patch("letsencrypt.client.zope.component.getUtility")
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

    @mock.patch("letsencrypt.client.enhancements")
    def test_enhance_config(self, mock_enhancements):
        config = ConfigHelper(redirect=True, hsts=False, uir=False)
        self.assertRaises(errors.Error,
                          self.client.enhance_config, ["foo.bar"], config)

        mock_enhancements.ask.return_value = True
        installer = mock.MagicMock()
        self.client.installer = installer

        self.client.enhance_config(["foo.bar"], config)
        installer.enhance.assert_called_once_with("foo.bar", "redirect", None)
        self.assertEqual(installer.save.call_count, 1)
        installer.restart.assert_called_once_with()

    @mock.patch("letsencrypt.client.enhancements")
    def test_enhance_config_no_ask(self, mock_enhancements):
        config = ConfigHelper(redirect=True, hsts=False, uir=False)
        self.assertRaises(errors.Error,
                          self.client.enhance_config, ["foo.bar"], config)

        mock_enhancements.ask.return_value = True
        installer = mock.MagicMock()
        self.client.installer = installer

        config = ConfigHelper(redirect=True, hsts=False, uir=False)
        self.client.enhance_config(["foo.bar"], config)
        installer.enhance.assert_called_with("foo.bar", "redirect", None)

        config = ConfigHelper(redirect=False, hsts=True, uir=False)
        self.client.enhance_config(["foo.bar"], config)
        installer.enhance.assert_called_with("foo.bar", "ensure-http-header",
                "Strict-Transport-Security")

        config = ConfigHelper(redirect=False, hsts=False, uir=True)
        self.client.enhance_config(["foo.bar"], config)
        installer.enhance.assert_called_with("foo.bar", "ensure-http-header",
                "Upgrade-Insecure-Requests")

        self.assertEqual(installer.save.call_count, 3)
        self.assertEqual(installer.restart.call_count, 3)

    def test_enhance_config_no_installer(self):
        config = ConfigHelper(redirect=True, hsts=False, uir=False)
        self.assertRaises(errors.Error,
                          self.client.enhance_config, ["foo.bar"], config)

    @mock.patch("letsencrypt.client.zope.component.getUtility")
    @mock.patch("letsencrypt.client.enhancements")
    def test_enhance_config_enhance_failure(self, mock_enhancements,
                                            mock_get_utility):
        mock_enhancements.ask.return_value = True
        installer = mock.MagicMock()
        self.client.installer = installer
        installer.enhance.side_effect = errors.PluginError

        config = ConfigHelper(redirect=True, hsts=False, uir=False)

        self.assertRaises(errors.PluginError,
                          self.client.enhance_config, ["foo.bar"], config)
        installer.recovery_routine.assert_called_once_with()
        self.assertEqual(mock_get_utility().add_message.call_count, 1)

    @mock.patch("letsencrypt.client.zope.component.getUtility")
    @mock.patch("letsencrypt.client.enhancements")
    def test_enhance_config_save_failure(self, mock_enhancements,
                                         mock_get_utility):
        mock_enhancements.ask.return_value = True
        installer = mock.MagicMock()
        self.client.installer = installer
        installer.save.side_effect = errors.PluginError

        config = ConfigHelper(redirect=True, hsts=False, uir=False)

        self.assertRaises(errors.PluginError,
                          self.client.enhance_config, ["foo.bar"], config)
        installer.recovery_routine.assert_called_once_with()
        self.assertEqual(mock_get_utility().add_message.call_count, 1)

    @mock.patch("letsencrypt.client.zope.component.getUtility")
    @mock.patch("letsencrypt.client.enhancements")
    def test_enhance_config_restart_failure(self, mock_enhancements,
                                            mock_get_utility):
        mock_enhancements.ask.return_value = True
        installer = mock.MagicMock()
        self.client.installer = installer
        installer.restart.side_effect = [errors.PluginError, None]

        config = ConfigHelper(redirect=True, hsts=False, uir=False)

        self.assertRaises(errors.PluginError,
                          self.client.enhance_config, ["foo.bar"], config)

        self.assertEqual(mock_get_utility().add_message.call_count, 1)
        installer.rollback_checkpoints.assert_called_once_with()
        self.assertEqual(installer.restart.call_count, 2)

    @mock.patch("letsencrypt.client.zope.component.getUtility")
    @mock.patch("letsencrypt.client.enhancements")
    def test_enhance_config_restart_failure2(self, mock_enhancements,
                                             mock_get_utility):
        mock_enhancements.ask.return_value = True
        installer = mock.MagicMock()
        self.client.installer = installer
        installer.restart.side_effect = errors.PluginError
        installer.rollback_checkpoints.side_effect = errors.ReverterError

        config = ConfigHelper(redirect=True, hsts=False, uir=False)

        self.assertRaises(errors.PluginError,
                          self.client.enhance_config, ["foo.bar"], config)
        self.assertEqual(mock_get_utility().add_message.call_count, 1)
        installer.rollback_checkpoints.assert_called_once_with()
        self.assertEqual(installer.restart.call_count, 1)


class RollbackTest(unittest.TestCase):
    """Tests for letsencrypt.client.rollback."""

    def setUp(self):
        self.m_install = mock.MagicMock()

    @classmethod
    def _call(cls, checkpoints, side_effect):
        from letsencrypt.client import rollback
        with mock.patch("letsencrypt.client"
                        ".display_ops.pick_installer") as mock_pick_installer:
            mock_pick_installer.side_effect = side_effect
            rollback(None, checkpoints, {}, mock.MagicMock())

    def test_no_problems(self):
        self._call(1, self.m_install)
        self.assertEqual(self.m_install().rollback_checkpoints.call_count, 1)
        self.assertEqual(self.m_install().restart.call_count, 1)

    def test_no_installer(self):
        self._call(1, None)  # Just make sure no exceptions are raised


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
