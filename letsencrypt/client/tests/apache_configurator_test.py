"""apache_configurator_test - unittests

A series of basic full integration tests to ensure that Letsencrypt is
still running smoothly.

.. note:: This code is not complete
.. note:: Do not document this code... it will change quickly

"""

import re
import os
import shutil
import sys
import unittest

from letsencrypt.client import apache_configurator
from letsencrypt.client import CONFIG
from letsencrypt.client import display
from letsencrypt.client import logger

# Some of these will likely go into a letsencrypt.tests.CONFIG file
TESTING_DIR = os.path.dirname(os.path.realpath(__file__))
UBUNTU_CONFIGS = os.path.join(TESTING_DIR, "debian_apache_2_4/")
TEMP_DIR = os.path.join(TESTING_DIR, "temp")


def setUpModule():
    """Run once before all unittests."""
    logger.setLogger(logger.FileLogger(sys.stdout))
    logger.setLogLevel(logger.INFO)
    display.set_display(display.NcursesDisplay())

    if not os.path.isdir(UBUNTU_CONFIGS):
        print "Please place the configuration directory: %s" % UBUNTU_CONFIGS
        sys.exit(1)

    shutil.copytree(UBUNTU_CONFIGS, TEMP_DIR, symlinks=True)


def tearDownModule():
    """Run once after all unittests."""
    shutil.rmtree(TEMP_DIR)


class TwoVhost80(unittest.TestCase):
    """Standard two http vhosts that are well configured."""

    def setUp(self):
        """Run before each and every tests."""
        # Final slash is currently important
        self.config_path = os.path.join(TEMP_DIR, "two_vhost_80/apache2/")

        # Using a new configurator every time allows the Configurator to clean
        # up after itself
        backup = os.path.join(TESTING_DIR, "backups")
        temp = os.path.join(TESTING_DIR, "temp_checkpoint")
        progress = os.path.join(backup, "IN_PROGRESS")
        self.config = apache_configurator.ApacheConfigurator(
            self.config_path, {"backup": backup, "temp": temp, "progress": progress}, (2, 4, 7))

        self.aug_path = "/files" + self.config_path

        prefix = os.path.join(TEMP_DIR, "two_vhost_80/apache2/sites-available/")
        aug_pre = "/files" + prefix
        self.vh_truth = []
        self.vh_truth.append(apache_configurator.VH(
            os.path.join(prefix + "encryption-example.conf"),
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

    def test_parse_file(self):
        """test parse_file.

        letsencrypt.conf is chosen as the test file as it will not be
        included during the normal course of execution.

        """
        file_path = os.path.join(
            self.config_path, "sites-available", "letsencrypt.conf")
        self.config._parse_file(file_path)

        # search for the httpd incl
        matches = self.config.aug.match(
            "/augeas/load/Httpd/incl [. ='%s']" % file_path)

        self.assertTrue(matches)

    def test_get_all_names(self):
        """test get_all_names."""
        names = self.config.get_all_names()
        self.assertTrue(set(names) == set(
            ['letsencrypt.demo', 'encryption-example.demo', 'ip-172-30-0-17']))

    def test_find_directive(self):
        """test find_directive."""
        test = self.config.find_directive(
            apache_configurator.case_i("Listen"), "443")
        # This will only look in enabled hosts
        test2 = self.config.find_directive(
            apache_configurator.case_i("documentroot"))
        self.assertTrue(len(test) == 2)
        self.assertTrue(len(test2) == 3)

    def test_get_virtual_hosts(self):
        """inefficient get_virtual_hosts check."""
        vhs = self.config.get_virtual_hosts()
        self.assertTrue(len(vhs) == 4)
        found = 0
        for vhost in vhs:
            for truth in self.vh_truth:
                if vhost == truth:
                    found += 1
                    break

        self.assertTrue(found == 4)

    def test_is_site_enabled(self):
        """test is_site_enabled"""
        self.assertTrue(self.config.is_site_enabled(self.vh_truth[0].file))
        self.assertTrue(not self.config.is_site_enabled(self.vh_truth[1].file))
        self.assertTrue(self.config.is_site_enabled(self.vh_truth[2].file))
        self.assertTrue(self.config.is_site_enabled(self.vh_truth[3].file))

    def test_add_dir(self):
        """test add_dir."""
        aug_default = "/files" + self.config.location["default"]
        self.config.add_dir(
            aug_default, "AddDirective", "test")

        self.assertTrue(
            self.config.find_directive("AddDirective", "test", aug_default))

    def test_deploy_cert(self):
        """test deploy_cert.

        This test modifies the default-ssl vhost SSL directives.

        """
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

        # debug_file(self.vh_truth[1].file)

        # Verify one directive was found in the correct file
        self.assertTrue(len(loc_cert) == 1 and
                        apache_configurator.get_file_path(loc_cert[0]) ==
                        self.vh_truth[1].file)

        self.assertTrue(len(loc_key) == 1 and
                        apache_configurator.get_file_path(loc_key[0]) ==
                        self.vh_truth[1].file)

        self.assertTrue(len(loc_chain) == 1 and
                        apache_configurator.get_file_path(loc_chain[0]) ==
                        self.vh_truth[1].file)

    def test_is_name_vhost(self):
        """test is_name_vhost."""
        self.assertTrue(self.config.is_name_vhost("*:80"))
        self.config.version = (2, 2)
        self.assertFalse(self.config.is_name_vhost("*:80"))

    def test_add_name_vhost(self):
        """test add_name_vhost."""
        self.config.add_name_vhost("*:443")
        # self.config.save(temporary=True)
        self.assertTrue(self.config.find_directive(
            "NameVirtualHost", re.escape("*:443")))

    def test_add_dir_to_ifmodssl(self):
        """test _add_dir_to_ifmodssl.

        .. todo:: test what happens when a bad path is given... ie. ports.conf
            doesn't exist

        """
        self.config._add_dir_to_ifmodssl(
            "/files" + self.config.location["default"], "FakeDirective", "123")

        matches = self.config.find_directive("FakeDirective", "123")

        self.assertTrue(len(matches) == 1)
        self.assertTrue("IfModule" in matches[0])

    def test_make_vhost_ssl(self):
        """test make_vhost_ssl."""
        ssl_vhost = self.config.make_vhost_ssl(self.vh_truth[0])

        self.assertTrue(
            ssl_vhost.file ==
            os.path.join(self.config_path, "sites-available",
                         "encryption-example-le-ssl.conf"))

        self.assertTrue(ssl_vhost.path ==
                        "/files" + ssl_vhost.file + "/IfModule/VirtualHost")
        self.assertTrue(ssl_vhost.addrs == ["*:443"])
        self.assertTrue(ssl_vhost.names == ["encryption-example.demo"])
        self.assertTrue(ssl_vhost.ssl)
        self.assertFalse(ssl_vhost.enabled)

        self.assertTrue(self.config.find_directive(
            "SSLCertificateFile", None, ssl_vhost.path))
        self.assertTrue(self.config.find_directive(
            "SSLCertificateKeyFile", None, ssl_vhost.path))
        self.assertTrue(self.config.find_directive(
            "Include", CONFIG.OPTIONS_SSL_CONF, ssl_vhost.path))

        self.assertTrue(self.config.is_name_vhost(self.vh_truth[0]) ==
                        self.config.is_name_vhost(ssl_vhost))

        self.assertTrue(len(self.config.vhosts) == 5)

    # def _verify_redirect(self, config_path):
    #     """Verifies that the vhost contains the REWRITE."""
    #     with open(config_path, 'r') as config_fd:
    #         conf = config_fd.read()

    #     return CONFIG.REWRITE_HTTPS_ARGS[1] in conf


def debug_file(filepath):
    """Print out the file."""
    with open(filepath, 'r')as file_d:
        print file_d.read()

if __name__ == '__main__':
    unittest.main()
