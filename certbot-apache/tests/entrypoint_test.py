"""Test for certbot_apache._internal.entrypoint for override class resolution"""
import sys
import unittest
from unittest import mock

import pytest

from certbot_apache._internal import configurator
from certbot_apache._internal import entrypoint


class EntryPointTest(unittest.TestCase):
    """Entrypoint tests"""

    _multiprocess_can_split_ = True

    def test_get_configurator(self):

        with mock.patch("certbot.util.get_os_info") as mock_info:
            for distro in entrypoint.OVERRIDE_CLASSES:
                return_value = (distro, "whatever")
                if distro == 'fedora_old':
                    return_value = ('fedora', '28')
                elif distro == 'fedora':
                    return_value = ('fedora', '29')
                mock_info.return_value = return_value
                self.assertEqual(entrypoint.get_configurator(),
                                 entrypoint.OVERRIDE_CLASSES[distro])

    def test_nonexistent_like(self):
        with mock.patch("certbot.util.get_os_info") as mock_info:
            mock_info.return_value = ("nonexistent", "irrelevant")
            with mock.patch("certbot.util.get_systemd_os_like") as mock_like:
                for like in entrypoint.OVERRIDE_CLASSES:
                    mock_like.return_value = [like]
                    self.assertEqual(entrypoint.get_configurator(),
                                     entrypoint.OVERRIDE_CLASSES[like])

    def test_nonexistent_generic(self):
        with mock.patch("certbot.util.get_os_info") as mock_info:
            mock_info.return_value = ("nonexistent", "irrelevant")
            with mock.patch("certbot.util.get_systemd_os_like") as mock_like:
                mock_like.return_value = ["unknown"]
                self.assertEqual(entrypoint.get_configurator(),
                                 configurator.ApacheConfigurator)


if __name__ == "__main__":
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover
