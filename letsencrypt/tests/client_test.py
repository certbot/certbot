"""Tests for letsencrypt.client."""
import os
import unittest
import pkg_resources
import shutil
import tempfile

import configobj
import mock

from letsencrypt import account
from letsencrypt import configuration
from letsencrypt import le_util


KEY = pkg_resources.resource_string(
    __name__, os.path.join("testdata", "rsa512_key.pem"))


class ClientTest(unittest.TestCase):
    """Tests for letsencrypt.client.Client."""

    def setUp(self):
        self.config = mock.MagicMock(no_verify_ssl=False)
        # pylint: disable=star-args
        self.account = mock.MagicMock(**{"key.pem": KEY})

        from letsencrypt.client import Client
        with mock.patch("letsencrypt.client.network2") as network2:
            self.client = Client(
                config=self.config, account_=self.account, dv_auth=None,
                installer=None)
        self.network2 = network2

    def test_init_network_verify_ssl(self):
        self.network2.Network.assert_called_once_with(
            mock.ANY, mock.ANY, verify_ssl=True)

    @mock.patch("letsencrypt.client.zope.component.getUtility")
    def test_report_new_account(self, mock_zope):
        # pylint: disable=protected-access
        self.config.config_dir = "/usr/bin/coffee"
        self.account.recovery_token = "ECCENTRIC INVISIBILITY RHINOCEROS"
        self.account.email = "rhino@jungle.io"

        self.client._report_new_account()
        call_list = mock_zope().add_message.call_args_list
        self.assertTrue(self.config.config_dir in call_list[0][0][0])
        self.assertTrue(self.account.recovery_token in call_list[1][0][0])
        self.assertTrue(self.account.email in call_list[1][0][0])

    @mock.patch("letsencrypt.client.zope.component.getUtility")
    def test_report_renewal_status(self, mock_zope):
        # pylint: disable=protected-access
        cert = mock.MagicMock()
        cert.configuration = configobj.ConfigObj()
        cert.configuration["renewal_configs_dir"] = "/etc/letsencrypt/configs"

        cert.configuration["autorenew"] = "True"
        cert.configuration["autodeploy"] = "True"
        self.client._report_renewal_status(cert)
        msg = mock_zope().add_message.call_args[0][0]
        self.assertTrue("renewal and deployment has been" in msg)
        self.assertTrue(cert.configuration["renewal_configs_dir"] in msg)

        cert.configuration["autorenew"] = "False"
        self.client._report_renewal_status(cert)
        msg = mock_zope().add_message.call_args[0][0]
        self.assertTrue("deployment but not automatic renewal" in msg)
        self.assertTrue(cert.configuration["renewal_configs_dir"] in msg)

        cert.configuration["autodeploy"] = "False"
        self.client._report_renewal_status(cert)
        msg = mock_zope().add_message.call_args[0][0]
        self.assertTrue("renewal and deployment has not" in msg)
        self.assertTrue(cert.configuration["renewal_configs_dir"] in msg)

        cert.configuration["autorenew"] = "True"
        self.client._report_renewal_status(cert)
        msg = mock_zope().add_message.call_args[0][0]
        self.assertTrue("renewal but not automatic deployment" in msg)
        self.assertTrue(cert.configuration["renewal_configs_dir"] in msg)

class DetermineAccountTest(unittest.TestCase):
    """Tests for letsencrypt.client.determine_authenticator."""

    def setUp(self):
        self.accounts_dir = tempfile.mkdtemp("accounts")
        account_keys_dir = os.path.join(self.accounts_dir, "keys")
        os.makedirs(account_keys_dir, 0o700)

        self.config = mock.MagicMock(
            spec=configuration.NamespaceConfig, accounts_dir=self.accounts_dir,
            account_keys_dir=account_keys_dir, rsa_key_size=2048,
            server="letsencrypt-demo.org")

    def tearDown(self):
        shutil.rmtree(self.accounts_dir)

    @mock.patch("letsencrypt.account.Account.from_prompts")
    @mock.patch("letsencrypt.client.display_ops.choose_account")
    def test_determine_account(self, mock_op, mock_prompt):
        """Test determine account"""
        from letsencrypt import client

        key = le_util.Key(tempfile.mkstemp()[1], "pem")
        test_acc = account.Account(self.config, key, "email1@gmail.com")
        mock_op.return_value = test_acc

        # Test 0
        mock_prompt.return_value = None
        self.assertTrue(client.determine_account(self.config) is None)

        # Test 1
        test_acc.save()
        acc = client.determine_account(self.config)
        self.assertEqual(acc.email, test_acc.email)

        # Test multiple
        self.assertFalse(mock_op.called)
        acc2 = account.Account(self.config, key)
        acc2.save()
        chosen_acc = client.determine_account(self.config)
        self.assertTrue(mock_op.called)
        self.assertTrue(chosen_acc.email, test_acc.email)


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
        self._call(1, None) # Just make sure no exceptions are raised


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
