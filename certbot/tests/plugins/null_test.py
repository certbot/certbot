"""Tests for certbot._internal.plugins.null."""
import unittest
from unittest import mock


class InstallerTest(unittest.TestCase):
    """Tests for certbot._internal.plugins.null.Installer."""

    def setUp(self):
        from certbot._internal.plugins.null import Installer
        self.installer = Installer(config=mock.MagicMock(), name="null")

    def test_it(self):
        self.assertIsInstance(self.installer.more_info(), str)
        self.assertEqual([], self.installer.get_all_names())
        self.assertEqual([], self.installer.supported_enhancements())


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
