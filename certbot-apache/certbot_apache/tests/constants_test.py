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

    @mock.patch("certbot.util.get_os_info")
    def test_get_default_value(self, os_info):
        os_info.return_value = ('Nonexistent Linux', '', '')
        self.assertEqual(constants.os_constant("vhost_root"),
                         "/etc/apache2/sites-available")

    @mock.patch("certbot.util.get_os_info")
    def test_get_default_constants(self, os_info):
        os_info.return_value = ('Nonexistent Linux', '', '')
        with mock.patch("certbot.util.get_systemd_os_like") as os_like:
            # Get defaults
            os_like.return_value = False
            c_hm = constants.os_constant("handle_mods")
            c_sr = constants.os_constant("server_root")
            self.assertFalse(c_hm)
            self.assertEqual(c_sr, "/etc/apache2")
            # Use darwin as like test target
            os_like.return_value = ["something", "nonexistent", "darwin"]
            d_vr = constants.os_constant("vhost_root")
            d_em = constants.os_constant("enmod")
            self.assertFalse(d_em)
            self.assertEqual(d_vr, "/etc/apache2/other")
