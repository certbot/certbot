"""Test for letsencrypt.client.apache_configurator."""
import os
import pkg_resources
import re
import shutil
import sys
import tempfile
import unittest

import mock

from letsencrypt.client import apache_configurator
from letsencrypt.client import CONFIG
from letsencrypt.client import display
from letsencrypt.client import errors
from letsencrypt.client import logger


UBUNTU_CONFIGS = pkg_resources.resource_filename(
    __name__, "testdata/debian_apache_2_4")


class TwoVhost80Test(unittest.TestCase):
    """Test two standard well configured HTTP vhosts."""

    def setUp(self):
        logger.setLogger(logger.FileLogger(sys.stdout))
        logger.setLogLevel(logger.INFO)
        display.set_display(display.NcursesDisplay())

        self.temp_dir = os.path.join(
            tempfile.mkdtemp("temp"), "debian_apache_2_4")
        self.config_dir = tempfile.mkdtemp("config")
        self.work_dir = tempfile.mkdtemp("work")

        shutil.copytree(UBUNTU_CONFIGS, self.temp_dir, symlinks=True)

        temp_options = pkg_resources.resource_filename(
            "letsencrypt.client", os.path.basename(CONFIG.OPTIONS_SSL_CONF))
        shutil.copyfile(
            temp_options, os.path.join(self.config_dir, "options-ssl.conf"))

        # Final slash is currently important
        self.config_path = os.path.join(self.temp_dir, "two_vhost_80/apache2/")
        self.ssl_options = os.path.join(self.config_dir, "options-ssl.conf")
        backups = os.path.join(self.work_dir, "backups")

        with mock.patch("letsencrypt.client.apache_configurator."
                        "subprocess.Popen") as mock_popen:
            # This just states that the ssl module is already loaded
            mock_popen().communicate.return_value = ("ssl_module", "")
            self.config = apache_configurator.ApacheConfigurator(
                self.config_path,
                {
                    "backup": backups,
                    "temp": os.path.join(self.work_dir, "temp_checkpoint"),
                    "progress": os.path.join(backups, "IN_PROGRESS"),
                    "config": self.config_dir,
                    "work": self.work_dir,
                },
                self.ssl_options,
                (2, 4, 7))

        prefix = os.path.join(
            self.temp_dir, "two_vhost_80/apache2/sites-available")
        aug_pre = "/files" + prefix
        self.vh_truth = []
        self.vh_truth.append(apache_configurator.VH(
            os.path.join(prefix, "encryption-example.conf"),
            os.path.join(aug_pre, "encryption-example.conf/VirtualHost"),
            ["*:80"], False, True))
        self.vh_truth.append(apache_configurator.VH(
            os.path.join(prefix, "default-ssl.conf"),
            os.path.join(aug_pre, "default-ssl.conf/IfModule/VirtualHost"),
            ["_default_:443"], True, False))
        self.vh_truth.append(apache_configurator.VH(
            os.path.join(prefix, "000-default.conf"),
            os.path.join(aug_pre, "000-default.conf/VirtualHost"),
            ["*:80"], False, True))
        self.vh_truth.append(apache_configurator.VH(
            os.path.join(prefix, "letsencrypt.conf"),
            os.path.join(aug_pre, "letsencrypt.conf/VirtualHost"),
            ["*:80"], False, True))
        self.vh_truth[0].add_name("encryption-example.demo")
        self.vh_truth[2].add_name("ip-172-30-0-17")
        self.vh_truth[3].add_name("letsencrypt.demo")

    def tearDown(self):
        shutil.rmtree(self.temp_dir)
        shutil.rmtree(self.config_dir)
        shutil.rmtree(self.work_dir)

    def test_parse_file(self):
        """Test parse_file.

        letsencrypt.conf is chosen as the test file as it will not be
        included during the normal course of execution.

        """
        file_path = os.path.join(
            self.config_path, "sites-available", "letsencrypt.conf")
        self.config._parse_file(file_path)  # pylint: disable=protected-access

        # search for the httpd incl
        matches = self.config.aug.match(
            "/augeas/load/Httpd/incl [. ='%s']" % file_path)

        self.assertTrue(matches)

    def test_get_all_names(self):
        names = self.config.get_all_names()
        self.assertEqual(set(names), set(
            ['letsencrypt.demo', 'encryption-example.demo', 'ip-172-30-0-17']))

    def test_find_directive(self):
        test = self.config.find_directive(
            apache_configurator.case_i("Listen"), "443")
        # This will only look in enabled hosts
        test2 = self.config.find_directive(
            apache_configurator.case_i("documentroot"))
        self.assertEqual(len(test), 2)
        self.assertEqual(len(test2), 3)

    def test_get_virtual_hosts(self):
        vhs = self.config.get_virtual_hosts()
        self.assertEqual(len(vhs), 4)
        found = 0
        for vhost in vhs:
            for truth in self.vh_truth:
                if vhost == truth:
                    found += 1
                    break

        self.assertEqual(found, 4)

    def test_is_site_enabled(self):
        self.assertTrue(self.config.is_site_enabled(self.vh_truth[0].filep))
        self.assertFalse(self.config.is_site_enabled(self.vh_truth[1].filep))
        self.assertTrue(self.config.is_site_enabled(self.vh_truth[2].filep))
        self.assertTrue(self.config.is_site_enabled(self.vh_truth[3].filep))

    def test_add_dir(self):
        aug_default = "/files" + self.config.location["default"]
        self.config.add_dir(
            aug_default, "AddDirective", "test")

        self.assertTrue(
            self.config.find_directive("AddDirective", "test", aug_default))

    def test_deploy_cert(self):
        self.config.deploy_cert(
            self.vh_truth[1],
            "example/cert.pem", "example/key.pem", "example/cert_chain.pem")

        loc_cert = self.config.find_directive(
            apache_configurator.case_i("sslcertificatefile"),
            re.escape("example/cert.pem"), self.vh_truth[1].path)
        loc_key = self.config.find_directive(
            apache_configurator.case_i("sslcertificateKeyfile"),
            re.escape("example/key.pem"), self.vh_truth[1].path)
        loc_chain = self.config.find_directive(
            apache_configurator.case_i("SSLCertificateChainFile"),
            re.escape("example/cert_chain.pem"), self.vh_truth[1].path)

        # Verify one directive was found in the correct file
        self.assertEqual(len(loc_cert), 1)
        self.assertEqual(apache_configurator.get_file_path(loc_cert[0]),
                         self.vh_truth[1].filep)

        self.assertEqual(len(loc_key), 1)
        self.assertEqual(apache_configurator.get_file_path(loc_key[0]),
                         self.vh_truth[1].filep)

        self.assertEqual(len(loc_chain), 1)
        self.assertEqual(apache_configurator.get_file_path(loc_chain[0]),
                         self.vh_truth[1].filep)

    def test_is_name_vhost(self):
        self.assertTrue(self.config.is_name_vhost("*:80"))
        self.config.version = (2, 2)
        self.assertFalse(self.config.is_name_vhost("*:80"))

    def test_add_name_vhost(self):
        self.config.add_name_vhost("*:443")
        # self.config.save(temporary=True)
        self.assertTrue(self.config.find_directive(
            "NameVirtualHost", re.escape("*:443")))

    def test_add_dir_to_ifmodssl(self):
        """test _add_dir_to_ifmodssl.

        Path must be valid before attempting to add to augeas

        """
        self.config._add_dir_to_ifmodssl(  # pylint: disable=protected-access
            "/files" + self.config.location["default"], "FakeDirective", "123")

        matches = self.config.find_directive("FakeDirective", "123")

        self.assertEqual(len(matches), 1)
        self.assertTrue("IfModule" in matches[0])

    def test_make_vhost_ssl(self):
        ssl_vhost = self.config.make_vhost_ssl(self.vh_truth[0])

        self.assertEqual(
            ssl_vhost.filep,
            os.path.join(self.config_path, "sites-available",
                         "encryption-example-le-ssl.conf"))

        self.assertEqual(ssl_vhost.path,
                         "/files" + ssl_vhost.filep + "/IfModule/VirtualHost")
        self.assertEqual(ssl_vhost.addrs, ["*:443"])
        self.assertEqual(ssl_vhost.names, ["encryption-example.demo"])
        self.assertTrue(ssl_vhost.ssl)
        self.assertFalse(ssl_vhost.enabled)

        self.assertTrue(self.config.find_directive(
            "SSLCertificateFile", None, ssl_vhost.path))
        self.assertTrue(self.config.find_directive(
            "SSLCertificateKeyFile", None, ssl_vhost.path))
        self.assertTrue(self.config.find_directive(
            "Include", self.ssl_options, ssl_vhost.path))

        self.assertEqual(self.config.is_name_vhost(self.vh_truth[0]),
                         self.config.is_name_vhost(ssl_vhost))

        self.assertEqual(len(self.config.vhosts), 5)

    @mock.patch("letsencrypt.client.apache_configurator."
                "subprocess.Popen")
    def test_get_version(self, mock_popen):
        mock_popen().communicate.return_value = (
            "Server Version: Apache/2.4.2 (Debian)", "")
        self.assertEqual(self.config.get_version(), (2, 4, 2))

        mock_popen().communicate.return_value = (
            "Server Version: Apache/2 (Linux)", "")
        self.assertEqual(self.config.get_version(), (2,))

        mock_popen().communicate.return_value = (
            "Server Version: Apache (Debian)", "")
        self.assertRaises(
            errors.LetsEncryptConfiguratorError, self.config.get_version)

        mock_popen().communicate.return_value = (
            "Server Version: Apache/2.3\n Apache/2.4.7", "")
        self.assertRaises(
            errors.LetsEncryptConfiguratorError, self.config.get_version)

        mock_popen.side_effect = OSError("Can't find program")
        self.assertRaises(
            errors.LetsEncryptConfiguratorError, self.config.get_version)


if __name__ == '__main__':
    unittest.main()
