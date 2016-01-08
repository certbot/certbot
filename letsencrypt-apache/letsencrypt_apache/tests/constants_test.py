"""Test for letsencrypt_apache.configurator."""

import mock
import unittest

from letsencrypt_apache import constants


class ConstantsTest(unittest.TestCase):

    @mock.patch("letsencrypt.le_util.get_os_info")
    def test_get_debian_value(self, os_info):
        os_info.return_value = ('Debian', '', '')
        self.assertEqual(constants.os_constant("vhost_root"),
                         "/etc/apache2/sites-available")

    @mock.patch("letsencrypt.le_util.get_os_info")
    def test_get_centos_value(self, os_info):
        os_info.return_value = ('CentOS Linux', '', '')
        self.assertEqual(constants.os_constant("vhost_root"),
                         "/etc/httpd/conf.d")

    @mock.patch("letsencrypt.le_util.get_os_info")
    def test_get_default_value(self, os_info):
        os_info.return_value = ('Nonexistent Linux', '', '')
        self.assertEqual(constants.os_constant("vhost_root"),
                         "/etc/apache2/sites-available")
