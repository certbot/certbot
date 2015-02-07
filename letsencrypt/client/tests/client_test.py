"""letsencrypt.client.client.py tests."""
import unittest

import mock

from letsencrypt.client import errors


class RollbackTest(unittest.TestCase):
    """Test the rollback function."""
    def setUp(self):
        self.m_install = mock.MagicMock()

    @classmethod
    def _call(cls, checkpoints):
        from letsencrypt.client.client import rollback
        rollback(checkpoints)

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
        mock_det.side_effect = [
            errors.MisconfigurationError, self.m_install]
        mock_input().generic_yesno.return_value = True

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
        mock_det.side_effect = errors.MisconfigurationError

        mock_input().generic_yesno.return_value = True

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
        mock_det.side_effect = errors.MisconfigurationError

        mock_input().generic_yesno.return_value = False

        self._call(1)

        # Neither is ever called
        self.assertEqual(self.m_install().rollback_checkpoints.call_count, 0)
        self.assertEqual(mock_rev().rollback_checkpoints.call_count, 0)

    @mock.patch("letsencrypt.client.client.determine_installer")
    def test_no_installer(self, mock_det):
        mock_det.return_value = None

        # Just make sure no exceptions are raised
        self._call(1)


if __name__ == '__main__':
    unittest.main()
