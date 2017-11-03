"""Test for certbot_apache.configurator non-overridden flow"""
import os
import shutil
import tempfile
import unittest

import mock

from certbot import errors

from certbot_apache.tests import util

class MultipleVhostsTestGeneric(util.ApacheTest):
    """Multiple vhost tests for non-debian distro"""

    _multiprocess_can_split_ = True

    def setUp(self):  # pylint: disable=arguments-differ
        super(MultipleVhostsTestGeneric, self).setUp()
        with mock.patch("certbot.util.get_systemd_os_like") as mock_like:
            mock_like.return_value = ["nonexistent"]
            self.config = util.get_apache_configurator(
                self.config_path, None, self.config_dir, self.work_dir,
                os_info=("nonexistent_distro", "7"))
            self.config = self.mock_deploy_cert(self.config)

        self.vh_truth = util.get_vh_truth(self.temp_dir,
                                          "debian_apache_2_4/multiple_vhosts")

    def mock_deploy_cert(self, config):
        """A test for a mock deploy cert"""
        self.config.real_deploy_cert = self.config.deploy_cert

        def mocked_deploy_cert(*args, **kwargs):
            """a helper to mock a deployed cert"""
            with mock.patch("certbot_apache.configurator.ApacheConfigurator.enable_mod"):
                config.real_deploy_cert(*args, **kwargs)
        self.config.deploy_cert = mocked_deploy_cert
        return self.config

    def test_enable_site_nondebian(self):
        inc_path = "/path/to/wherever"
        vhost = self.vh_truth[0]
        vhost.enabled = False
        vhost.filep = inc_path
        self.assertFalse(self.config.parser.find_dir("Include", inc_path))
        self.assertFalse(
            os.path.dirname(inc_path) in self.config.parser.existing_paths)
        self.config.enable_site(vhost)
        self.assertTrue(self.config.parser.find_dir("Include", inc_path))
        self.assertTrue(
            os.path.dirname(inc_path) in self.config.parser.existing_paths)
        self.assertTrue(
            os.path.basename(inc_path) in self.config.parser.existing_paths[
                os.path.dirname(inc_path)])

    def test_deploy_cert_not_parsed_path(self):
        # Make sure that we add include to root config for vhosts when
        # handle-sites is false
        self.config.parser.modules.add("ssl_module")
        self.config.parser.modules.add("mod_ssl.c")
        self.config.parser.modules.add("socache_shmcb_module")
        tmp_path = os.path.realpath(tempfile.mkdtemp("vhostroot"))
        os.chmod(tmp_path, 0o755)
        mock_p = "certbot_apache.configurator.ApacheConfigurator._get_ssl_vhost_path"
        mock_a = "certbot_apache.parser.ApacheParser.add_include"

        with mock.patch(mock_p) as mock_path:
            mock_path.return_value = os.path.join(tmp_path, "whatever.conf")
            with mock.patch(mock_a) as mock_add:
                self.config.deploy_cert(
                    "encryption-example.demo",
                    "example/cert.pem", "example/key.pem",
                    "example/cert_chain.pem")
                # Test that we actually called add_include
                self.assertTrue(mock_add.called)
        shutil.rmtree(tmp_path)

    @mock.patch("certbot_apache.parser.ApacheParser.parsed_in_original")
    def test_choose_vhost_and_servername_addition(self, mock_parsed):
        ret_vh = self.vh_truth[8]
        ret_vh.enabled = True
        self.config.enable_site(ret_vh)
        # Make sure that we return early
        self.assertFalse(mock_parsed.called)

    def test_enable_mod_unsupported(self):
        self.assertRaises(errors.MisconfigurationError,
                          self.config.enable_mod,
                          "whatever")

if __name__ == "__main__":
    unittest.main()  # pragma: no cover
