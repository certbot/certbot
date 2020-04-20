"""Test for certbot_apache._internal.configurator for Centos overrides"""
import unittest

try:
    import mock
except ImportError: # pragma: no cover
    from unittest import mock # type: ignore

from certbot import errors
from certbot.compat import filesystem
from certbot.compat import os
from certbot_apache._internal import obj
from certbot_apache._internal import override_centos
import util


def get_vh_truth(temp_dir, config_name):
    """Return the ground truth for the specified directory."""
    prefix = os.path.join(
        temp_dir, config_name, "httpd/conf.d")

    aug_pre = "/files" + prefix
    vh_truth = [
        obj.VirtualHost(
            os.path.join(prefix, "centos.example.com.conf"),
            os.path.join(aug_pre, "centos.example.com.conf/VirtualHost"),
            {obj.Addr.fromstring("*:80")},
            False, True, "centos.example.com"),
        obj.VirtualHost(
            os.path.join(prefix, "ssl.conf"),
            os.path.join(aug_pre, "ssl.conf/VirtualHost"),
            {obj.Addr.fromstring("_default_:443")},
            True, True, None)
    ]
    return vh_truth

class FedoraRestartTest(util.ApacheTest):
    """Tests for Fedora specific self-signed certificate override"""

    def setUp(self):  # pylint: disable=arguments-differ
        test_dir = "centos7_apache/apache"
        config_root = "centos7_apache/apache/httpd"
        vhost_root = "centos7_apache/apache/httpd/conf.d"
        super(FedoraRestartTest, self).setUp(test_dir=test_dir,
                                             config_root=config_root,
                                             vhost_root=vhost_root)
        self.config = util.get_apache_configurator(
            self.config_path, self.vhost_path, self.config_dir, self.work_dir,
            os_info="fedora_old")
        self.vh_truth = get_vh_truth(
            self.temp_dir, "centos7_apache/apache")

    def _run_fedora_test(self):
        self.assertIsInstance(self.config, override_centos.CentOSConfigurator)
        with mock.patch("certbot.util.get_os_info") as mock_info:
            mock_info.return_value = ["fedora", "28"]
            self.config.config_test()

    def test_non_fedora_error(self):
        c_test = "certbot_apache._internal.configurator.ApacheConfigurator.config_test"
        with mock.patch(c_test) as mock_test:
            mock_test.side_effect = errors.MisconfigurationError
            with mock.patch("certbot.util.get_os_info") as mock_info:
                mock_info.return_value = ["not_fedora"]
                self.assertRaises(errors.MisconfigurationError,
                                  self.config.config_test)

    def test_fedora_restart_error(self):
        c_test = "certbot_apache._internal.configurator.ApacheConfigurator.config_test"
        with mock.patch(c_test) as mock_test:
            # First call raises error, second doesn't
            mock_test.side_effect = [errors.MisconfigurationError, '']
            with mock.patch("certbot.util.run_script") as mock_run:
                mock_run.side_effect = errors.SubprocessError
                self.assertRaises(errors.MisconfigurationError,
                                  self._run_fedora_test)

    def test_fedora_restart(self):
        c_test = "certbot_apache._internal.configurator.ApacheConfigurator.config_test"
        with mock.patch(c_test) as mock_test:
            with mock.patch("certbot.util.run_script") as mock_run:
                # First call raises error, second doesn't
                mock_test.side_effect = [errors.MisconfigurationError, '']
                self._run_fedora_test()
                self.assertEqual(mock_test.call_count, 2)
                self.assertEqual(mock_run.call_args[0][0],
                                ['systemctl', 'restart', 'httpd'])


class MultipleVhostsTestCentOS(util.ApacheTest):
    """Multiple vhost tests for CentOS / RHEL family of distros"""

    _multiprocess_can_split_ = True

    def setUp(self):  # pylint: disable=arguments-differ
        test_dir = "centos7_apache/apache"
        config_root = "centos7_apache/apache/httpd"
        vhost_root = "centos7_apache/apache/httpd/conf.d"
        super(MultipleVhostsTestCentOS, self).setUp(test_dir=test_dir,
                                                    config_root=config_root,
                                                    vhost_root=vhost_root)

        self.config = util.get_apache_configurator(
            self.config_path, self.vhost_path, self.config_dir, self.work_dir,
            os_info="centos")
        self.vh_truth = get_vh_truth(
            self.temp_dir, "centos7_apache/apache")

    def test_get_parser(self):
        self.assertIsInstance(self.config.parser, override_centos.CentOSParser)

    @mock.patch("certbot_apache._internal.apache_util._get_runtime_cfg")
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
            if command == ['apachectl', '-t', '-D', 'DUMP_RUN_CFG']:
                return define_val
            elif command == ['apachectl', '-t', '-D', 'DUMP_MODULES']:
                return mod_val
            return ""
        mock_get.side_effect = mock_get_cfg
        self.config.parser.modules = {}
        self.config.parser.variables = {}

        with mock.patch("certbot.util.get_os_info") as mock_osi:
            # Make sure we have the have the CentOS httpd constants
            mock_osi.return_value = ("centos", "7")
            self.config.parser.update_runtime_variables()

        self.assertEqual(mock_get.call_count, 3)
        self.assertEqual(len(self.config.parser.modules), 4)
        self.assertEqual(len(self.config.parser.variables), 2)
        self.assertTrue("TEST2" in self.config.parser.variables.keys())
        self.assertTrue("mod_another.c" in self.config.parser.modules)

    def test_get_virtual_hosts(self):
        """Make sure all vhosts are being properly found."""
        vhs = self.config.get_virtual_hosts()
        self.assertEqual(len(vhs), 2)
        found = 0

        for vhost in vhs:
            for centos_truth in self.vh_truth:
                if vhost == centos_truth:
                    found += 1
                    break
            else:
                raise Exception("Missed: %s" % vhost)  # pragma: no cover
        self.assertEqual(found, 2)

    @mock.patch("certbot_apache._internal.apache_util._get_runtime_cfg")
    def test_get_sysconfig_vars(self, mock_cfg):
        """Make sure we read the sysconfig OPTIONS variable correctly"""
        # Return nothing for the process calls
        mock_cfg.return_value = ""
        self.config.parser.sysconfig_filep = filesystem.realpath(
            os.path.join(self.config.parser.root, "../sysconfig/httpd"))
        self.config.parser.variables = {}

        with mock.patch("certbot.util.get_os_info") as mock_osi:
            # Make sure we have the have the CentOS httpd constants
            mock_osi.return_value = ("centos", "7")
            self.config.parser.update_runtime_variables()

        self.assertTrue("mock_define" in self.config.parser.variables.keys())
        self.assertTrue("mock_define_too" in self.config.parser.variables.keys())
        self.assertTrue("mock_value" in self.config.parser.variables.keys())
        self.assertEqual("TRUE", self.config.parser.variables["mock_value"])
        self.assertTrue("MOCK_NOSEP" in self.config.parser.variables.keys())
        self.assertEqual("NOSEP_VAL", self.config.parser.variables["NOSEP_TWO"])

    @mock.patch("certbot_apache._internal.configurator.util.run_script")
    def test_alt_restart_works(self, mock_run_script):
        mock_run_script.side_effect = [None, errors.SubprocessError, None]
        self.config.restart()
        self.assertEqual(mock_run_script.call_count, 3)

    @mock.patch("certbot_apache._internal.configurator.util.run_script")
    def test_alt_restart_errors(self, mock_run_script):
        mock_run_script.side_effect = [None,
                                       errors.SubprocessError,
                                       errors.SubprocessError]
        self.assertRaises(errors.MisconfigurationError, self.config.restart)


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
