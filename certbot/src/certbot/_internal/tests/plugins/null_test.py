"""Tests for certbot._internal.plugins.null."""
import sys
import unittest
from unittest import mock

import pytest


class InstallerTest(unittest.TestCase):
    """Tests for certbot._internal.plugins.null.Installer."""

    def setUp(self):
        from certbot._internal.plugins.null import Installer
        self.installer = Installer(config=mock.MagicMock(), name="null")

    def test_it(self):
        assert isinstance(self.installer.more_info(), str)
        assert [] == self.installer.get_all_names()
        assert [] == self.installer.supported_enhancements()


if __name__ == "__main__":
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover
