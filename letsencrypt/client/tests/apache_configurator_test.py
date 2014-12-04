"""apache_configurator_test - unittests

A series of basic full integration tests to ensure that Letsencrypt is
still running smoothly.

.. note:: This code is not complete
.. note:: Do not document this code... it will change quickly

"""

import os
import shutil
import tarfile
import unittest
import sys

from letsencrypt.client import apache_configurator
from letsencrypt.client import CONFIG
from letsencrypt.client import display
from letsencrypt.client import le_util
from letsencrypt.client import logger

# Some of these will likely go into a letsencrypt.tests.CONFIG file
TESTING_DIR = "/home/ubuntu/testing/"
UBUNTU_CONFIGS = os.path.join(TESTING_DIR, "ubuntu_apache_2_4/")
TEMP_DIR = os.path.join(TESTING_DIR, "temp")

# This will end up going into the repo...
CONFIG_TGZ_URL = "https://jdkasten.com/projects/config.tgz"


def setUpModule():
    logger.setLogger(logger.FileLogger(sys.stdout))
    logger.setLogLevel(logger.INFO)
    display.set_display(display.NcursesDisplay())

    if not os.path.isdir(UBUNTU_CONFIGS):
        print "Please place the configuration directory: %s" % UBUNTU_CONFIGS
        sys.exit(1)
    shutil.copytree(UBUNTU_CONFIGS, TEMP_DIR, symlinks=True)


def tearDownModule():
    shutil.rmtree(TEMP_DIR)


class TwoVhosts_80(unittest.TestCase):

    def setUp(self):
        # Final slash is currently important
        self.config_path = os.path.join(TEMP_DIR, "two_vhost_80/apache2/")
        self.config = apache_configurator.ApacheConfigurator(
            self.config_path, (2, 4, 7))

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
        """get_virtual_hosts."""
        vhs = self.config.get_virtual_hosts()
        self.assertTrue(len(vhs) == 4)
        failed = False
        for vhost in vhs:
            for truth in self.vh_truth:
                if vhost == truth:
                    break
            failed = True

        self.assertTrue(failed)

    def test_is_site_enabled(self):
        """test is_site_enabled"""
        self.assertTrue(self.config.is_site_enabled(self.vh_truth[0].file))
        self.assertTrue(not self.config.is_site_enabled(self.vh_truth[1].file))
        self.assertTrue(self.config.is_site_enabled(self.vh_truth[2].file))
        self.assertTrue(self.config.is_site_enabled(self.vh_truth[3].file))

    # def test_deploy_cert(self):
    #     """test deploy_cert."""
    #     self.config.deploy_cert(
    #         self.vh_truth[1],
    #         "example/cert.pem", "example/key.pem", "example/cert_chain.pem")

    #     loc_cert = self.config.find_directive(
    #         apache_configurator.case_i(
    #             "sslcertificatefile"), "example/cert.pem")
    #     loc_key = self.config.find_directive(
    #         apache_configurator.case_i(
    #             "sslcertificateKeyfile"), "example/key.pem")
    #     loc_chain = self.config.find_directive(
    #         apache_configurator.case_i(
    #             "SSLCertificateChainFile"), "example/chain.pem")

    #     self.assertTrue(len(loc_cert) == 1 and
    #            apache_configurator.get_file_path(
    #                loc_cert[0]) == self.vh_truth[1].file)

    #     self.assertTrue(len(loc_key) == 1 and
    #            apache_configurator.get_file_path(
    #                loc_key[0]) == self.vh_truth[1].file)

    #     self.assertTrue(len(loc_chain) == 1 and
    #            apache_configurator.get_file_path(
    #                loc_chain[0]) == self.vh_truth[1].file)

    def test_is_name_vhost(self):
        """test is_name_vhost."""
        self.assertTrue(not self.config.is_name_vhost("*:80"))

    # def test_add_name_vhost(self):
    #     """test add_name_vhost."""
    #     self.config.add_name_vhost("*:443")
    #     self.config.save(temporary=True)

    #     self.assertTrue(self.config.is_name_vhost("*:443"))

    def _verify_redirect(self, config_path):
        with open(config_path, 'r') as config_fd:
            conf = config_fd.read()

        return CONFIG.REWRITE_HTTPS_ARGS[1] in conf


if __name__ == '__main__':
    unittest.main()
# def download_unpack_tests(url=CONFIG_TGZ_URL):
#     r = requests.get(url)
#     local_tgz_file = os.path.join(TESTING_DIR, 'ubuntu_2_4.tgz')
#     with open(local_tgz_file, 'w') as tgz_file:
#         tgz_file.write(r.content)

#     if tarfile.is_tarfile(local_tgz_file):
#         tar = tarfile.open(local_tgz_file)
#         tar.extractall()
#         tar.close()
