"""letsencrypt.client.client.py tests."""
import unittest

import mock

from letsencrypt.client import errors


class DetermineAuthenticatorTest(unittest.TestCase):
    def setUp(self):
        from letsencrypt.client.apache.configurator import ApacheConfigurator
        from letsencrypt.client.standalone_authenticator import (
            StandaloneAuthenticator)

        self.mock_stand = mock.MagicMock(
            spec=StandaloneAuthenticator, description="Apache Web Server")
        self.mock_apache = mock.MagicMock(
            spec=ApacheConfigurator, description="Standalone Authenticator")

        self.mock_config = mock.Mock()

        self.all_auths = [self.mock_apache, self.mock_stand]

    @classmethod
    def _call(cls, all_auths):
        from letsencrypt.client.client import determine_authenticator
        return determine_authenticator(all_auths)

    @mock.patch("letsencrypt.client.client.display_ops.choose_authenticator")
    def test_accept_two(self, mock_choose):
        mock_choose.return_value = self.mock_stand()
        self.assertEqual(self._call(self.all_auths), self.mock_stand())

    def test_accept_one(self):
        self.mock_apache.prepare.return_value = self.mock_apache
        self.assertEqual(
            self._call(self.all_auths[:1]), self.mock_apache)

    def test_no_installation_one(self):
        self.mock_apache.prepare.side_effect = errors.NoInstallationError
        self.assertEqual(self._call(self.all_auths), self.mock_stand)

    def test_no_installations(self):
        self.mock_apache.prepare.side_effect = errors.NoInstallationError
        self.mock_stand.prepare.side_effect = errors.NoInstallationError
        self.assertRaises(errors.Error, self._call, self.all_auths)

    @mock.patch("letsencrypt.client.client.logging")
    @mock.patch("letsencrypt.client.client.display_ops.choose_authenticator")
    def test_misconfigured(self, mock_choose, unused_log):
        self.mock_apache.prepare.side_effect = errors.MisconfigurationError
        mock_choose.return_value = self.mock_apache
        self.assertTrue(self._call(self.all_auths) is None)


class RollbackTest(unittest.TestCase):
    """Test the rollback function."""
    def setUp(self):
        from letsencrypt.client.apache.configurator import ApacheConfigurator
        self.m_install = mock.MagicMock(spec=ApacheConfigurator)

    @classmethod
    def _call(cls, checkpoints):
        from letsencrypt.client.client import rollback
        rollback(checkpoints, mock.MagicMock())

    @mock.patch("letsencrypt.client.client.determine_installer")
    def test_no_problems(self, mock_det):
        mock_det.side_effect = self.m_install

        self._call(1)

        self.assertEqual(self.m_install().rollback_checkpoints.call_count, 1)
        self.assertEqual(self.m_install().restart.call_count, 1)

    @mock.patch("letsencrypt.client.client.determine_installer")
    def test_no_installer(self, mock_det):
        mock_det.return_value = None

        # Just make sure no exceptions are raised
        self._call(1)


if __name__ == "__main__":
    unittest.main()
