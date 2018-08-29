"""Test for certbot_apache.configurator for Debian overrides"""
import os
import shutil
import unittest

import mock

from certbot import errors

from certbot_apache import apache_util
from certbot_apache import obj
from certbot_apache.tests import util


class MultipleVhostsTestDebian(util.ApacheTest):
    """Multiple vhost tests for Debian family of distros"""

    _multiprocess_can_split_ = True

    def setUp(self):  # pylint: disable=arguments-differ
        super(MultipleVhostsTestDebian, self).setUp()
        self.config = util.get_apache_configurator(
            self.config_path, self.vhost_path, self.config_dir, self.work_dir,
            os_info="debian")
        self.config = self.mock_deploy_cert(self.config)
        self.vh_truth = util.get_vh_truth(self.temp_dir,
                                          "debian_apache_2_4/multiple_vhosts")

    def mock_deploy_cert(self, config):
        """A test for a mock deploy cert"""
        config.real_deploy_cert = self.config.deploy_cert

        def mocked_deploy_cert(*args, **kwargs):
            """a helper to mock a deployed cert"""
            g_mod = "certbot_apache.configurator.ApacheConfigurator.enable_mod"
            d_mod = "certbot_apache.override_debian.DebianConfigurator.enable_mod"
            with mock.patch(g_mod):
                with mock.patch(d_mod):
                    config.real_deploy_cert(*args, **kwargs)
        self.config.deploy_cert = mocked_deploy_cert
        return self.config

    def test_enable_mod_unsupported_dirs(self):
        shutil.rmtree(os.path.join(self.config.parser.root, "mods-enabled"))
        self.assertRaises(
            errors.NotSupportedError, self.config.enable_mod, "ssl")

    @mock.patch("certbot.util.run_script")
    @mock.patch("certbot.util.exe_exists")
    @mock.patch("certbot_apache.parser.subprocess.Popen")
    def test_enable_mod(self, mock_popen, mock_exe_exists, mock_run_script):
        mock_popen().communicate.return_value = ("Define: DUMP_RUN_CFG", "")
        mock_popen().returncode = 0
        mock_exe_exists.return_value = True

        self.config.enable_mod("ssl")
        self.assertTrue("ssl_module" in self.config.parser.modules)
        self.assertTrue("mod_ssl.c" in self.config.parser.modules)

        self.assertTrue(mock_run_script.called)

    def test_deploy_cert_enable_new_vhost(self):
        # Create
        ssl_vhost = self.config.make_vhost_ssl(self.vh_truth[0])
        self.config.parser.modules.add("ssl_module")
        self.config.parser.modules.add("mod_ssl.c")
        self.assertFalse(ssl_vhost.enabled)
        self.config.deploy_cert(
            "encryption-example.demo", "example/cert.pem", "example/key.pem",
            "example/cert_chain.pem", "example/fullchain.pem")
        self.assertTrue(ssl_vhost.enabled)
        # Make sure that we don't error out if symlink already exists
        ssl_vhost.enabled = False
        self.assertFalse(ssl_vhost.enabled)
        self.config.deploy_cert(
            "encryption-example.demo", "example/cert.pem", "example/key.pem",
            "example/cert_chain.pem", "example/fullchain.pem")
        self.assertTrue(ssl_vhost.enabled)

    def test_enable_site_failure(self):
        self.config.parser.root = "/tmp/nonexistent"
        with mock.patch("os.path.isdir") as mock_dir:
            mock_dir.return_value = True
            with mock.patch("os.path.islink") as mock_link:
                mock_link.return_value = False
                self.assertRaises(
                    errors.NotSupportedError,
                    self.config.enable_site,
                    obj.VirtualHost("asdf", "afsaf", set(), False, False))

    def test_deploy_cert_newssl(self):
        self.config = util.get_apache_configurator(
            self.config_path, self.vhost_path, self.config_dir,
            self.work_dir, version=(2, 4, 16))
        self.config = self.mock_deploy_cert(self.config)
        self.config.parser.modules.add("ssl_module")
        self.config.parser.modules.add("mod_ssl.c")

        # Get the default 443 vhost
        self.config.assoc["random.demo"] = self.vh_truth[1]
        self.config.deploy_cert(
            "random.demo", "example/cert.pem", "example/key.pem",
            "example/cert_chain.pem", "example/fullchain.pem")
        self.config.save()

        # Verify ssl_module was enabled.
        self.assertTrue(self.vh_truth[1].enabled)
        self.assertTrue("ssl_module" in self.config.parser.modules)

        loc_cert = self.config.parser.find_dir(
            "sslcertificatefile", "example/fullchain.pem",
            self.vh_truth[1].path)
        loc_key = self.config.parser.find_dir(
            "sslcertificateKeyfile", "example/key.pem", self.vh_truth[1].path)

        # Verify one directive was found in the correct file
        self.assertEqual(len(loc_cert), 1)
        self.assertEqual(
            apache_util.get_file_path(loc_cert[0]),
            self.vh_truth[1].filep)

        self.assertEqual(len(loc_key), 1)
        self.assertEqual(
            apache_util.get_file_path(loc_key[0]),
            self.vh_truth[1].filep)

    def test_deploy_cert_newssl_no_fullchain(self):
        self.config = util.get_apache_configurator(
            self.config_path, self.vhost_path, self.config_dir,
            self.work_dir, version=(2, 4, 16))
        self.config = self.mock_deploy_cert(self.config)
        self.config.parser.modules.add("ssl_module")
        self.config.parser.modules.add("mod_ssl.c")

        # Get the default 443 vhost
        self.config.assoc["random.demo"] = self.vh_truth[1]
        self.assertRaises(errors.PluginError,
                          lambda: self.config.deploy_cert(
                              "random.demo", "example/cert.pem",
                              "example/key.pem"))

    def test_deploy_cert_old_apache_no_chain(self):
        self.config = util.get_apache_configurator(
            self.config_path, self.vhost_path, self.config_dir,
            self.work_dir, version=(2, 4, 7))
        self.config = self.mock_deploy_cert(self.config)
        self.config.parser.modules.add("ssl_module")
        self.config.parser.modules.add("mod_ssl.c")

        # Get the default 443 vhost
        self.config.assoc["random.demo"] = self.vh_truth[1]
        self.assertRaises(errors.PluginError,
                          lambda: self.config.deploy_cert(
                              "random.demo", "example/cert.pem",
                              "example/key.pem"))

    @mock.patch("certbot.util.run_script")
    @mock.patch("certbot.util.exe_exists")
    def test_ocsp_stapling_enable_mod(self, mock_exe, _):
        self.config.parser.update_runtime_variables = mock.Mock()
        self.config.parser.modules.add("mod_ssl.c")
        self.config.get_version = mock.Mock(return_value=(2, 4, 7))
        mock_exe.return_value = True
        # This will create an ssl vhost for certbot.demo
        self.config.choose_vhost("certbot.demo")
        self.config.enhance("certbot.demo", "staple-ocsp")
        self.assertTrue("socache_shmcb_module" in self.config.parser.modules)

    @mock.patch("certbot.util.run_script")
    @mock.patch("certbot.util.exe_exists")
    def test_ensure_http_header_enable_mod(self, mock_exe, _):
        self.config.parser.update_runtime_variables = mock.Mock()
        self.config.parser.modules.add("mod_ssl.c")
        mock_exe.return_value = True

        # This will create an ssl vhost for certbot.demo
        self.config.choose_vhost("certbot.demo")
        self.config.enhance("certbot.demo", "ensure-http-header",
                            "Strict-Transport-Security")
        self.assertTrue("headers_module" in self.config.parser.modules)

    @mock.patch("certbot.util.run_script")
    @mock.patch("certbot.util.exe_exists")
    def test_redirect_enable_mod(self, mock_exe, _):
        self.config.parser.update_runtime_variables = mock.Mock()
        mock_exe.return_value = True
        self.config.get_version = mock.Mock(return_value=(2, 2))
        # This will create an ssl vhost for certbot.demo
        self.config.choose_vhost("certbot.demo")
        self.config.enhance("certbot.demo", "redirect")
        self.assertTrue("rewrite_module" in self.config.parser.modules)

    def test_enable_site_already_enabled(self):
        self.assertTrue(self.vh_truth[1].enabled)
        self.config.enable_site(self.vh_truth[1])

    def test_enable_site_call_parent(self):
        with mock.patch(
            "certbot_apache.configurator.ApacheConfigurator.enable_site") as e_s:
            self.config.parser.root = "/tmp/nonexistent"
            vh = self.vh_truth[0]
            vh.enabled = False
            self.config.enable_site(vh)
            self.assertTrue(e_s.called)

    @mock.patch("certbot.util.exe_exists")
    def test_enable_mod_no_disable(self, mock_exe_exists):
        mock_exe_exists.return_value = False
        self.assertRaises(
            errors.MisconfigurationError, self.config.enable_mod, "ssl")

if __name__ == "__main__":
    unittest.main()  # pragma: no cover
