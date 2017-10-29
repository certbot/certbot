# pylint: disable=duplicate-code
"""Test for certbot_apache.configurator for Centos overrides"""
import os
import shutil

import mock

from certbot_apache import obj
from certbot_apache.tests import util

def get_vh_truth(temp_dir, config_name):
    """Return the ground truth for the specified directory."""
    prefix = os.path.join(
        temp_dir, config_name, "httpd/conf.d")

    aug_pre = "/files" + prefix
    vh_truth = [
        obj.VirtualHost(
            os.path.join(prefix, "centos.example.com.conf"),
            os.path.join(aug_pre, "centos.example.com.conf/VirtualHost"),
            set([obj.Addr.fromstring("*:80")]),
            False, True, "centos.example.com"),
        obj.VirtualHost(
            os.path.join(prefix, "ssl.conf"),
            os.path.join(aug_pre, "ssl.conf/VirtualHost"),
            set([obj.Addr.fromstring("_default_:443")]),
            True, True, None)
    ]
    return vh_truth

class MultipleVhostsTestCentOS(util.ApacheTest):
    """Multiple vhost tests for non-debian distro"""

    _multiprocess_can_split_ = True

    def setUp(self):  # pylint: disable=arguments-differ
        test_dir = "centos7_apache/apache"
        config_root = "centos7_apache/apache/httpd"
        vhost_root = "centos7_apache/apache/httpd/conf.d"
        super(MultipleVhostsTestCentOS, self).setUp(test_dir=test_dir,
                                                    config_root=config_root,
                                                    vhost_root=vhost_root)

        from certbot_apache.constants import os_constant
        orig_os_constant = os_constant
        def mock_os_constant(key, vhost_path=self.vhost_path):
            """Mock default vhost path"""
            if key == "vhost_root":
                return vhost_path
            else:
                return orig_os_constant(key)
        with mock.patch("certbot.util.get_os_info") as mock_osi:
            mock_osi.return_value = ("centos", "7")
            with mock.patch(
                "certbot_apache.constants.os_constant") as mock_c:
                mock_c.side_effect = mock_os_constant
                self.config = util.get_apache_configurator(
                    self.config_path, None, self.config_dir, self.work_dir)
            self.vh_truth = get_vh_truth(
                self.temp_dir, "centos7_apache/apache")

    def tearDown(self):
        shutil.rmtree(self.temp_dir)
        shutil.rmtree(self.config_dir)
        shutil.rmtree(self.work_dir)

    def test_get_parser(self):
        from certbot_apache import override_centos
        self.assertTrue(isinstance(self.config.parser,
                                   override_centos.CentOSParser))

    @mock.patch("certbot_apache.parser.ApacheParser._get_runtime_cfg")
    def test_opportunistic_httpd_runtime_parsing(self, mock_get):
        define_val = (
            'Define: TEST1\n'
            'Define: TEST2\n'
            'Define: DUMP_RUN_CFG\n'
        )
        mod_val = (
            'Loaded Modules:\n'
            ' mock_module (static)\n'
            ' another_module (static)\n'
        )
        def mock_get_cfg(command):
            """Mock httpd process stdout"""
            if command == ['apache2ctl', '-t', '-D', 'DUMP_RUN_CFG']:
                return define_val
            elif command == ['apache2ctl', '-t', '-D', 'DUMP_MODULES']:
                return mod_val
            return ""
        mock_get.side_effect = mock_get_cfg
        self.config.parser.modules = set()
        self.config.parser.variables = {}
        self.config.parser.update_runtime_variables()

        self.assertEquals(mock_get.call_count, 3)
        self.assertEquals(len(self.config.parser.modules), 4)
        self.assertEquals(len(self.config.parser.variables), 2)
        self.assertTrue("TEST2" in self.config.parser.variables.keys())
        self.assertTrue("mod_another.c" in self.config.parser.modules)

    def test_get_virtual_hosts(self):
        """Make sure all vhosts are being properly found."""
        vhs = self.config.get_virtual_hosts()
        self.assertEqual(len(vhs), 2)
        found = 0

        for vhost in vhs:
            for truth in self.vh_truth:
                if vhost == truth:
                    found += 1
                    break
            else:
                raise Exception("Missed: %s" % vhost)  # pragma: no cover
        self.assertEqual(found, 2)

    def test_get_sysconfig_vars(self):
        """Make sure we read the sysconfig OPTIONS variable correctly"""
        self.config.parser.sysconfig_filep = os.path.realpath(
            os.path.join(self.config.parser.root, "../sysconfig/httpd"))
        self.config.parser.variables = {}
        self.config.parser.update_runtime_variables()
        self.assertTrue("mock_define" in self.config.parser.variables.keys())
        self.assertTrue("mock_define_too" in self.config.parser.variables.keys())
        self.assertTrue("mock_value" in self.config.parser.variables.keys())
        self.assertEqual("TRUE", self.config.parser.variables["mock_value"])
