"""Test for certbot_apache._internal.entrypoint for override class resolution"""
import unittest

try:
    import mock
except ImportError: # pragma: no cover
    from unittest import mock # type: ignore

from certbot_apache._internal import configurator
from certbot_apache._internal import entrypoint
from certbot_apache._internal import override_centos


class EntryPointTest(unittest.TestCase):
    """Entrypoint tests"""

    _multiprocess_can_split_ = True

    def test_get_configurator(self):

        with mock.patch("certbot.util.get_os_info") as mock_info:
            for distro in entrypoint.OVERRIDE_CLASSES:
                return_value = (distro, "whatever")
                if distro == 'fedora':
                    return_value = ('fedora', '29')
                mock_info.return_value = return_value
                self.assertEqual(entrypoint.get_configurator(),
                                 entrypoint.OVERRIDE_CLASSES[distro])

    @mock.patch("certbot.util.get_os_info")
    def test_old_centos_rhel_and_fedora(self, mock_get_os_info):
        for os_info in [("centos", "7"), ("rhel", "7"), ("fedora", "28"), ("scientific", "6")]:
            mock_get_os_info.return_value = os_info
            self.assertEqual(entrypoint.get_configurator(),
                            override_centos.OldCentOSConfigurator)

    @mock.patch("certbot.util.get_os_info")
    def test_new_rhel_derived(self, mock_get_os_info):
        for os_info in [("centos", "9"), ("rhel", "9"), ("oracle", "9")]:
            mock_get_os_info.return_value = os_info
            self.assertEqual(entrypoint.get_configurator(),
                            override_centos.CentOSConfigurator)

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
    unittest.main()  # pragma: no cover
