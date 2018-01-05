"""Test for certbot_apache.configurator for Gentoo overrides"""
import os
import unittest

import mock

from certbot_apache import override_gentoo
from certbot_apache import obj
from certbot_apache.tests import util

def get_vh_truth(temp_dir, config_name):
    """Return the ground truth for the specified directory."""
    prefix = os.path.join(
        temp_dir, config_name, "apache2/vhosts.d")

    aug_pre = "/files" + prefix
    vh_truth = [
        obj.VirtualHost(
            os.path.join(prefix, "gentoo.example.com.conf"),
            os.path.join(aug_pre, "gentoo.example.com.conf/VirtualHost"),
            set([obj.Addr.fromstring("*:80")]),
            False, True, "gentoo.example.com"),
        obj.VirtualHost(
            os.path.join(prefix, "00_default_vhost.conf"),
            os.path.join(aug_pre, "00_default_vhost.conf/IfDefine/VirtualHost"),
            set([obj.Addr.fromstring("*:80")]),
            False, True, "localhost"),
        obj.VirtualHost(
            os.path.join(prefix, "00_default_ssl_vhost.conf"),
            os.path.join(aug_pre,
                         "00_default_ssl_vhost.conf" +
                         "/IfDefine/IfDefine/IfModule/VirtualHost"),
            set([obj.Addr.fromstring("_default_:443")]),
            True, True, "localhost")
    ]
    return vh_truth

class MultipleVhostsTestGentoo(util.ApacheTest):
    """Multiple vhost tests for non-debian distro"""

    _multiprocess_can_split_ = True

    def setUp(self):  # pylint: disable=arguments-differ
        test_dir = "gentoo_apache/apache"
        config_root = "gentoo_apache/apache/apache2"
        vhost_root = "gentoo_apache/apache/apache2/vhosts.d"
        super(MultipleVhostsTestGentoo, self).setUp(test_dir=test_dir,
                                                    config_root=config_root,
                                                    vhost_root=vhost_root)

        with mock.patch("certbot_apache.override_gentoo.GentooParser.update_runtime_variables"):
            self.config = util.get_apache_configurator(
                self.config_path, self.vhost_path, self.config_dir, self.work_dir,
                os_info="gentoo")
        self.vh_truth = get_vh_truth(
            self.temp_dir, "gentoo_apache/apache")

    def test_get_parser(self):
        self.assertTrue(isinstance(self.config.parser,
                                   override_gentoo.GentooParser))

    def test_get_virtual_hosts(self):
        """Make sure all vhosts are being properly found."""
        vhs = self.config.get_virtual_hosts()
        self.assertEqual(len(vhs), 3)
        found = 0

        for vhost in vhs:
            for gentoo_truth in self.vh_truth:
                if vhost == gentoo_truth:
                    found += 1
                    break
            else:
                raise Exception("Missed: %s" % vhost)  # pragma: no cover
        self.assertEqual(found, 3)

    def test_get_sysconfig_vars(self):
        """Make sure we read the Gentoo APACHE2_OPTS variable correctly"""
        defines = ['DEFAULT_VHOST', 'INFO',
                   'SSL', 'SSL_DEFAULT_VHOST', 'LANGUAGE']
        self.config.parser.apacheconfig_filep = os.path.realpath(
            os.path.join(self.config.parser.root, "../conf.d/apache2"))
        self.config.parser.variables = {}
        with mock.patch("certbot_apache.override_gentoo.GentooParser.update_modules"):
            self.config.parser.update_runtime_variables()
        for define in defines:
            self.assertTrue(define in self.config.parser.variables.keys())

    @mock.patch("certbot_apache.parser.ApacheParser.parse_from_subprocess")
    def test_no_binary_configdump(self, mock_subprocess):
        """Make sure we don't call binary dumps other than modules from Apache
        as this is not supported in Gentoo currently"""

        with mock.patch("certbot_apache.override_gentoo.GentooParser.update_modules"):
            self.config.parser.update_runtime_variables()
            self.config.parser.reset_modules()
        self.assertFalse(mock_subprocess.called)

        self.config.parser.update_runtime_variables()
        self.config.parser.reset_modules()
        self.assertTrue(mock_subprocess.called)

    @mock.patch("certbot_apache.parser.ApacheParser._get_runtime_cfg")
    def test_opportunistic_httpd_runtime_parsing(self, mock_get):
        mod_val = (
            'Loaded Modules:\n'
            ' mock_module (static)\n'
            ' another_module (static)\n'
        )
        def mock_get_cfg(command):
            """Mock httpd process stdout"""
            if command == ['apache2ctl', 'modules']:
                return mod_val
        mock_get.side_effect = mock_get_cfg
        self.config.parser.modules = set()

        with mock.patch("certbot.util.get_os_info") as mock_osi:
            # Make sure we have the have the CentOS httpd constants
            mock_osi.return_value = ("gentoo", "123")
            self.config.parser.update_runtime_variables()

        self.assertEquals(mock_get.call_count, 1)
        self.assertEquals(len(self.config.parser.modules), 4)
        self.assertTrue("mod_another.c" in self.config.parser.modules)

if __name__ == "__main__":
    unittest.main()  # pragma: no cover
