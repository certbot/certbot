"""Tests for certbot.plugins.null."""
import unittest

import mock


class InstallerTest(unittest.TestCase):
    """Tests for certbot.plugins.null.Installer."""

    def setUp(self):
        from certbot.plugins.null import Installer
        self.installer = Installer(config=mock.MagicMock(), name="null")

    def test_it(self):
        self.assertTrue(isinstance(self.installer.more_info(), str))
        self.assertEqual([], self.installer.get_all_names())
        self.assertEqual([], self.installer.supported_enhancements())
        self.assertEqual([], self.installer.get_all_certs_keys())


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
