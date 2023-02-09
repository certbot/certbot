"""Test for certbot_apache._internal.configurator for Debian overrides"""
import shutil
import sys
import unittest
from unittest import mock

import pytest

from certbot import errors
from certbot.compat import os
from certbot.tests import util as certbot_util
from certbot_apache._internal import apache_util
from certbot_apache._internal import obj
import util


class MultipleVhostsTestDebian(util.ApacheTest):
    """Multiple vhost tests for Debian family of distros"""

    _multiprocess_can_split_ = True

    def setUp(self):  # pylint: disable=arguments-differ
        super().setUp()
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
            g_mod = "certbot_apache._internal.configurator.ApacheConfigurator.enable_mod"
            d_mod = "certbot_apache._internal.override_debian.DebianConfigurator.enable_mod"
            with mock.patch(g_mod):
                with mock.patch(d_mod):
                    config.real_deploy_cert(*args, **kwargs)
        self.config.deploy_cert = mocked_deploy_cert
        return self.config

    def test_enable_mod_unsupported_dirs(self):
        shutil.rmtree(os.path.join(self.config.parser.root, "mods-enabled"))
        self.assertRaises(errors.NotSupportedError, self.config.enable_mod, "ssl")

    @mock.patch("certbot.util.run_script")
    @mock.patch("certbot.util.exe_exists")
    @mock.patch("certbot_apache._internal.apache_util.subprocess.run")
    def test_enable_mod(self, mock_run, mock_exe_exists, mock_run_script):
        mock_run.return_value.stdout = "Define: DUMP_RUN_CFG"
        mock_run.return_value.stderr = ""
        mock_run.return_value.returncode = 0
        mock_exe_exists.return_value = True

        self.config.enable_mod("ssl")
        self.assertIn("ssl_module", self.config.parser.modules)
        self.assertIn("mod_ssl.c", self.config.parser.modules)

        self.assertIs(mock_run_script.called, True)

    def test_deploy_cert_enable_new_vhost(self):
        # Create
        ssl_vhost = self.config.make_vhost_ssl(self.vh_truth[0])
        self.config.parser.modules["ssl_module"] = None
        self.config.parser.modules["mod_ssl.c"] = None
        self.assertIs(ssl_vhost.enabled, False)
        with certbot_util.patch_display_util():
            self.config.deploy_cert(
                "encryption-example.demo", "example/cert.pem", "example/key.pem",
                "example/cert_chain.pem", "example/fullchain.pem")
            self.assertIs(ssl_vhost.enabled, True)
            # Make sure that we don't error out if symlink already exists
            ssl_vhost.enabled = False
            self.assertIs(ssl_vhost.enabled, False)
            self.config.deploy_cert(
                "encryption-example.demo", "example/cert.pem", "example/key.pem",
                "example/cert_chain.pem", "example/fullchain.pem")
            self.assertIs(ssl_vhost.enabled, True)

    def test_enable_site_failure(self):
        self.config.parser.root = "/tmp/nonexistent"
        with mock.patch("certbot.compat.os.path.isdir") as mock_dir:
            mock_dir.return_value = True
            with mock.patch("certbot.compat.os.path.islink") as mock_link:
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
        self.config.parser.modules["ssl_module"] = None
        self.config.parser.modules["mod_ssl.c"] = None

        # Get the default 443 vhost
        self.config.assoc["random.demo"] = self.vh_truth[1]
        with certbot_util.patch_display_util():
            self.config.deploy_cert(
                "random.demo", "example/cert.pem", "example/key.pem",
                "example/cert_chain.pem", "example/fullchain.pem")
        self.config.save()

        # Verify ssl_module was enabled.
        self.assertIs(self.vh_truth[1].enabled, True)
        self.assertIn("ssl_module", self.config.parser.modules)

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
        self.config.parser.modules["ssl_module"] = None
        self.config.parser.modules["mod_ssl.c"] = None

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
        self.config.parser.modules["ssl_module"] = None
        self.config.parser.modules["mod_ssl.c"] = None

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
        self.config.parser.modules["mod_ssl.c"] = None
        self.config.get_version = mock.Mock(return_value=(2, 4, 7))
        mock_exe.return_value = True
        # This will create an ssl vhost for certbot.demo
        self.config.choose_vhost("certbot.demo")
        self.config.enhance("certbot.demo", "staple-ocsp")
        self.assertIn("socache_shmcb_module", self.config.parser.modules)

    @mock.patch("certbot.util.run_script")
    @mock.patch("certbot.util.exe_exists")
    def test_ensure_http_header_enable_mod(self, mock_exe, _):
        self.config.parser.update_runtime_variables = mock.Mock()
        self.config.parser.modules["mod_ssl.c"] = None
        mock_exe.return_value = True

        # This will create an ssl vhost for certbot.demo
        self.config.choose_vhost("certbot.demo")
        self.config.enhance("certbot.demo", "ensure-http-header",
                            "Strict-Transport-Security")
        self.assertIn("headers_module", self.config.parser.modules)

    @mock.patch("certbot.util.run_script")
    @mock.patch("certbot.util.exe_exists")
    def test_redirect_enable_mod(self, mock_exe, _):
        self.config.parser.update_runtime_variables = mock.Mock()
        mock_exe.return_value = True
        self.config.get_version = mock.Mock(return_value=(2, 2))
        # This will create an ssl vhost for certbot.demo
        self.config.choose_vhost("certbot.demo")
        self.config.enhance("certbot.demo", "redirect")
        self.assertIn("rewrite_module", self.config.parser.modules)

    def test_enable_site_already_enabled(self):
        self.assertIs(self.vh_truth[1].enabled, True)
        self.config.enable_site(self.vh_truth[1])

    def test_enable_site_call_parent(self):
        with mock.patch(
            "certbot_apache._internal.configurator.ApacheConfigurator.enable_site") as e_s:
            self.config.parser.root = "/tmp/nonexistent"
            vh = self.vh_truth[0]
            vh.enabled = False
            self.config.enable_site(vh)
            self.assertIs(e_s.called, True)

    @mock.patch("certbot.util.exe_exists")
    def test_enable_mod_no_disable(self, mock_exe_exists):
        mock_exe_exists.return_value = False
        self.assertRaises(
            errors.MisconfigurationError, self.config.enable_mod, "ssl")

if __name__ == "__main__":
    sys.exit(pytest.main([__file__]))  # pragma: no cover
