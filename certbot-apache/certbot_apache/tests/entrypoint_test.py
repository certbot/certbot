"""Test for certbot_apache.entrypoint for override class resolution"""
import unittest

import mock

from certbot_apache import configurator
from certbot_apache import entrypoint
from certbot_apache import override_arch
from certbot_apache import override_darwin
from certbot_apache import override_debian
from certbot_apache import override_centos
from certbot_apache import override_gentoo
from certbot_apache import override_suse


class EntryPointTest(unittest.TestCase):
    """Multiple vhost tests for CentOS / RHEL family of distros"""

    _multiprocess_can_split_ = True


    OVERRIDES = {
        "arch": override_arch.ArchConfigurator,
        "darwin": override_darwin.DarwinConfigurator,
        "debian": override_debian.DebianConfigurator,
        "ubuntu": override_debian.DebianConfigurator,
        "centos": override_centos.CentOSConfigurator,
        "centos linux": override_centos.CentOSConfigurator,
        "fedora": override_centos.CentOSConfigurator,
        "red hat enterprise linux server": override_centos.CentOSConfigurator,
        "rhel": override_centos.CentOSConfigurator,
        "amazon": override_centos.CentOSConfigurator,
        "gentoo": override_gentoo.GentooConfigurator,
        "gentoo base system": override_gentoo.GentooConfigurator,
        "opensuse": override_suse.OpenSUSEConfigurator,
        "suse": override_suse.OpenSUSEConfigurator,
    }

    def test_get_configurator(self):

        with mock.patch("certbot.util.get_os_info") as mock_info:
            for distro in self.OVERRIDES.keys():
                mock_info.return_value = (distro, "whatever")
                self.assertEqual(entrypoint.get_configurator(),
                                 self.OVERRIDES[distro])

    def test_find_all_overrides(self):
        from certbot_apache import override
        self.assertEqual(len(override.OVERRIDE_CLASSES), len(self.OVERRIDES))

    def test_nonexistent_like(self):
        with mock.patch("certbot.util.get_os_info") as mock_info:
            mock_info.return_value = ("nonexistent", "irrelevant")
            with mock.patch("certbot.util.get_systemd_os_like") as mock_like:
                mock_like.return_value = ["debian"]
                self.assertEqual(entrypoint.get_configurator(),
                                 override_debian.DebianConfigurator)

    def test_nonexistent_generic(self):
        with mock.patch("certbot.util.get_os_info") as mock_info:
            mock_info.return_value = ("nonexistent", "irrelevant")
            with mock.patch("certbot.util.get_systemd_os_like") as mock_like:
                mock_like.return_value = ["unknonwn"]
                self.assertEqual(entrypoint.get_configurator(),
                                 configurator.ApacheConfigurator)


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
