"""Test for certbot_apache.configurator."""

import mock
import unittest

from certbot_apache import constants


class ConstantsTest(unittest.TestCase):

    @mock.patch("certbot.util.get_os_info")
    def test_get_debian_value(self, os_info):
        os_info.return_value = ('Debian', '', '')
        self.assertEqual(constants.os_constant("vhost_root"),
                         "/etc/apache2/sites-available")

    @mock.patch("certbot.util.get_os_info")
    def test_get_centos_value(self, os_info):
        os_info.return_value = ('CentOS Linux', '', '')
        self.assertEqual(constants.os_constant("vhost_root"),
                         "/etc/httpd/conf.d")

    @mock.patch("certbot.util.get_systemd_os_like")
    @mock.patch("certbot.util.get_os_info")
    def test_get_default_values(self, os_info, os_like):
        os_info.return_value = ('Nonexistent Linux', '', '')
        os_like.return_value = {}
        self.assertFalse(constants.os_constant("handle_mods"))
        self.assertEqual(constants.os_constant("server_root"), "/etc/apache2")
        self.assertEqual(constants.os_constant("vhost_root"),
                         "/etc/apache2/sites-available")

    @mock.patch("certbot.util.get_systemd_os_like")
    @mock.patch("certbot.util.get_os_info")
    def test_get_darwin_like_values(self, os_info, os_like):
        os_info.return_value = ('Nonexistent Linux', '', '')
        os_like.return_value = ["something", "nonexistent", "darwin"]
        self.assertFalse(constants.os_constant("enmod"))
        self.assertEqual(constants.os_constant("vhost_root"),
                         "/etc/apache2/other")

    @mock.patch("certbot.util.get_systemd_os_like")
    @mock.patch("certbot.util.get_os_info")
    def test_get_configurator_os_like(self, os_info, os_like):
        from certbot_apache import override_debian
        mock_le_config = mock.Mock()
        version = (2, 4, 11)
        os_info.return_value = ('Nonexistent Linux', '', '')
        os_like.return_value = ["debian"]
        with mock.patch(
            "certbot_apache.configurator.ApacheConfigurator.__init__"):
            config = constants.get_configurator(
                config=mock_le_config,
                name="x",
                version=version)
            self.assertTrue(isinstance(config,
                                       override_debian.DebianConfigurator))

if __name__ == "__main__":
    unittest.main()  # pragma: no cover
