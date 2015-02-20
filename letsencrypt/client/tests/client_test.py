"""letsencrypt.client.client.py tests."""
import unittest

import mock

from letsencrypt.client import errors


class DetermineAuthenticatorTest(unittest.TestCase):
    def setUp(self):
        from letsencrypt.client.apache.configurator import ApacheConfigurator
        from letsencrypt.client.standalone_authenticator \
            import StandaloneAuthenticator

        self.mock_stand = mock.MagicMock(spec=StandaloneAuthenticator)
        self.mock_apache = mock.MagicMock(spec=ApacheConfigurator)

        self.mock_config = mock.Mock()

        self.all_auths = [
            ("Apache Web Server", self.mock_apache, self.mock_config),
            ("Standalone", self.mock_stand),
        ]

    @classmethod
    def _call(cls, all_auths):
        from letsencrypt.client.client import determine_authenticator
        return determine_authenticator(all_auths)

    @mock.patch("letsencrypt.client.client.ops.choose_authenticator")
    def test_accept_two(self, mock_choose):
        mock_choose.return_value = self.mock_stand()
        self.assertEqual(self._call(self.all_auths), self.mock_stand())

    def test_accept_one(self):
        self.assertEqual(
            self._call(self.all_auths[:1]), self.mock_apache(self.mock_config))

    def test_no_installation_one(self):
        self.mock_apache.side_effect = errors.LetsEncryptNoInstallationError

        self.assertEqual(self._call(self.all_auths), self.mock_stand())

    def test_no_installations(self):
        self.mock_apache.side_effect = errors.LetsEncryptNoInstallationError
        self.mock_stand.side_effect = errors.LetsEncryptNoInstallationError

        self.assertTrue(self._call(self.all_auths) is None)

    @mock.patch("letsencrypt.client.client.logging")
    @mock.patch("letsencrypt.client.client.ops.choose_authenticator")
    def test_misconfigured(self, mock_choose, mock_log):  # pylint: disable=unused-argument
        self.mock_apache.side_effect = errors.LetsEncryptMisconfigurationError
        mock_choose.return_value = self.mock_apache

        self.assertRaises(SystemExit, self._call, self.all_auths)

    def test_too_many_params(self):
        self.assertRaises(
            errors.LetsEncryptClientError,
            self._call,
            [("desc", self.mock_apache, "1", "2", "3", "4", "5")])


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

    @mock.patch("letsencrypt.client.client.zope.component.getUtility")
    @mock.patch("letsencrypt.client.reverter.Reverter")
    @mock.patch("letsencrypt.client.client.determine_installer")
    def test_misconfiguration_fixed(self, mock_det, mock_rev, mock_input):
        mock_det.side_effect = [errors.LetsEncryptMisconfigurationError,
                                self.m_install]
        mock_input().yesno.return_value = True

        self._call(1)

        # Don't rollback twice... (only on one object)
        self.assertEqual(self.m_install().rollback_checkpoints.call_count, 0)
        self.assertEqual(mock_rev().rollback_checkpoints.call_count, 1)

        # Only restart once
        self.assertEqual(self.m_install.restart.call_count, 1)

    @mock.patch("letsencrypt.client.client.zope.component.getUtility")
    @mock.patch("letsencrypt.client.client.logging.warning")
    @mock.patch("letsencrypt.client.reverter.Reverter")
    @mock.patch("letsencrypt.client.client.determine_installer")
    def test_misconfiguration_remains(
            self, mock_det, mock_rev, mock_warn, mock_input):
        mock_det.side_effect = errors.LetsEncryptMisconfigurationError

        mock_input().yesno.return_value = True

        self._call(1)

        # Don't rollback twice... (only on one object)
        self.assertEqual(self.m_install().rollback_checkpoints.call_count, 0)
        self.assertEqual(mock_rev().rollback_checkpoints.call_count, 1)

        # Never call restart because init never succeeds
        self.assertEqual(self.m_install().restart.call_count, 0)
        # There should be a warning about the remaining problem
        self.assertEqual(mock_warn.call_count, 1)

    @mock.patch("letsencrypt.client.client.zope.component.getUtility")
    @mock.patch("letsencrypt.client.reverter.Reverter")
    @mock.patch("letsencrypt.client.client.determine_installer")
    def test_user_decides_to_manually_investigate(
            self, mock_det, mock_rev, mock_input):
        mock_det.side_effect = errors.LetsEncryptMisconfigurationError

        mock_input().yesno.return_value = False

        self._call(1)

        # Neither is ever called
        self.assertEqual(self.m_install().rollback_checkpoints.call_count, 0)
        self.assertEqual(mock_rev().rollback_checkpoints.call_count, 0)

    @mock.patch("letsencrypt.client.client.determine_installer")
    def test_no_installer(self, mock_det):
        mock_det.return_value = None

        # Just make sure no exceptions are raised
        self._call(1)


if __name__ == "__main__":
    unittest.main()
