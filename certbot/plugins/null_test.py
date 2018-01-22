"""Tests for certbot.plugins.null."""
import shutil
import tempfile
import unittest
import six

import mock


class InstallerTest(unittest.TestCase):
    """Tests for certbot.plugins.null.Installer."""

    def setUp(self):
        from certbot.plugins.null import Installer
        self.config_dir = tempfile.mkdtemp()
        self.config = mock.MagicMock(config_dir=self.config_dir)
        self.installer = Installer(config=self.config, name="null")

    def tearDown(self):
        shutil.rmtree(self.config_dir)

    def test_it(self):
        self.assertTrue(isinstance(self.installer.more_info(), six.string_types))
        self.assertEqual([], self.installer.get_all_names())
        self.assertEqual([], self.installer.supported_enhancements())


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
