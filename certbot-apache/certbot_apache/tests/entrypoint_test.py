"""Test for certbot_apache.entrypoint for override class resolution"""
import unittest

import mock

from certbot_apache import configurator
from certbot_apache import entrypoint

class EntryPointTest(unittest.TestCase):
    """Entrypoint tests"""

    _multiprocess_can_split_ = True

    def test_get_configurator(self):

        with mock.patch("certbot.util.get_os_info") as mock_info:
            for distro in entrypoint.OVERRIDE_CLASSES.keys():
                mock_info.return_value = (distro, "whatever")
                self.assertEqual(entrypoint.get_configurator(),
                                 entrypoint.OVERRIDE_CLASSES[distro])

    def test_nonexistent_like(self):
        with mock.patch("certbot.util.get_os_info") as mock_info:
            mock_info.return_value = ("nonexistent", "irrelevant")
            with mock.patch("certbot.util.get_systemd_os_like") as mock_like:
                for like in entrypoint.OVERRIDE_CLASSES.keys():
                    mock_like.return_value = [like]
                    self.assertEqual(entrypoint.get_configurator(),
                                     entrypoint.OVERRIDE_CLASSES[like])

    def test_nonexistent_generic(self):
        with mock.patch("certbot.util.get_os_info") as mock_info:
            mock_info.return_value = ("nonexistent", "irrelevant")
            with mock.patch("certbot.util.get_systemd_os_like") as mock_like:
                mock_like.return_value = ["unknonwn"]
                self.assertEqual(entrypoint.get_configurator(),
                                 configurator.ApacheConfigurator)


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
