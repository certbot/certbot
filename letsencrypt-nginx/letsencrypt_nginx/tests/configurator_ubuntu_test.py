# pylint: disable=too-many-public-methods
"""Test for letsencrypt_nginx.configurator."""
import os
import shutil
import unittest

from letsencrypt_nginx.tests import util

class NginxConfiguratorUbuntuTest(util.NginxTest):
    """Test a semi complex vhost configuration."""

    def setUp(self):
        self.config_path = None
        self.config_dir = None
        self.work_dir = None

    def tearDown(self):
        shutil.rmtree(self.temp_dir)
        shutil.rmtree(self.config_dir)
        shutil.rmtree(self.work_dir)

    def test_choose_vhost_auto_detects_conf_dir(self):
        for data_dir in ["ubuntu_nginx_1_9_3", "ubuntu_nginx_1_4_6"]:
            self._test_choose_vhost_auto_detects_conf_dir(data_dir)

    def _test_choose_vhost_auto_detects_conf_dir(self, data_dir):
        self.setupData(data_dir)

        config = util.get_nginx_configurator(
            self.config_path, self.config_dir, self.work_dir)

        conf_path = {'new.com': os.path.join(data_dir, "sites-enabled/new.com.conf"),
                   'example.com': os.path.join(data_dir, "sites-enabled/existing")}

        for name in conf_path:
            vhost = config.choose_vhost(name)
            path = os.path.relpath(vhost.filep, self.temp_dir)

            self.assertEqual(set([name]), vhost.names)
            self.assertEqual(conf_path[name], path)

if __name__ == "__main__":
    unittest.main()  # pragma: no cover
