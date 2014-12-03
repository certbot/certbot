"""test_letsencrypt - Integration Test

A series of basic full integration tests to ensure that Letsencrypt is
still running smoothly.

.. note:: This code is not complete nor has it been tested
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
# I have not put this up on my website yet... it will not work
# This might end up going into the repo... but this is more of
# a user run test as opposed to a Travis CI test.
CONFIG_TGZ_URL = "https://jdkasten.com/letsencrypt/config.tgz"


def setUpModule():
    logger.setLogger(logger.FileLogger(sys.stdout))
    logger.setLogLevel(logger.INFO)
    display.set_display(display.NcursesDisplay())

    if not os.path.isdir(UBUNTU_CONFIGS):
        print "Please place the configuration directory: %s" % UBUNTU_CONFIGS
        sys.exit(1)
    shutil.copytree(UBUNTU_CONFIGS, TEMP_DIR)

def tearDownModule():
    shutil.rmtree(TEMP_DIR)

class TwoVhosts_80(unittest.TestCase):
    def setUp(self):
        config_path = os.path.join(UBUNTU_CONFIGS, "two_vhosts_*80/apache2")
        sites_path = os.path.join(UBUNTU_CONFIGS, "two_vhosts_*80/sites")

        self.config = apache_configurator.ApacheConfigurator(config_path, 2.47)

        prefix = os.path.join(TEMP_DIR, "sites-available")
        aug_pre = os.path.join("/files", prefix)
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

    def test_get_all_names(self):
        names = self.config.get_all_names()

        print names
        self.assertTrue(set(names) == set(
            ["letsencrypt.demo", "encryption-example.com", "ip-172-30-0-17"]))

    def test_find_directive(self):
        self.assertTrue(
            len(self.config.find_directive(
                apache_configurator.case_i("Listen"), "443") == 2))
        self.assertTrue(
            len(self.config.find_directive(
                apache_configurator.case_i("documentroot"))) == 4)

    def test_get_virtual_hosts(self):
        vhs = self.config.get_virtual_hosts()

        self.assertTrue(len(vhs) == 4)
        self.assertTrue(set(self.vh_truth) == set(vhs))

    def test_is_site_enabled(self):
        self.assertTrue(self.config.is_site_enabled(self.vh_truth[0].file))
        self.assertTrue(not self.config.is_site_enabled(self.vh_truth[1].file))
        self.assertTrue(self.config.is_site_enabled(self.vh_truth[2].file))
        self.assertTrue(self.config.is_site_enabled(self.vh_truth[3].file))

    def test_deploy_cert(self):
        self.config.deploy_cert(
            self.vh_truth[1],
            "example/cert.pem", "example/key.pem", "example/cert_chain.pem")

        loc_cert = self.config.find_directive(
            apache_configurator.case_i("sslcertificatefile"), "example/cert.pem")
        loc_key = self.config.find_directive(
            apache_configurator.case_i("sslcertificateKeyfile"), "example/key.pem")
        loc_chain = self.config.find_directive(
            apache_configurator.case_i("SSLCertificateChainFile"), "example/chain.pem")

        self.assertTrue(len(loc_cert) == 1 and
               apache_configurator.get_file_path(
                   loc_cert[0]) == self.vh_truth[1].file)

        self.assertTrue(len(loc_key) == 1 and
               apache_configurator.get_file_path(
                   loc_key[0]) == self.vh_truth[1].file)

        self.assertTrue(len(loc_chain) == 1 and
               apache_configurator.get_file_path(
                   loc_chain[0]) == self.vh_truth[1].file)

    def test_is_name_vhost(self):
        self.assertTrue(not self.config.is_name_vhost("*:80"))

    def test_add_name_vhost(self):
        self.config.add_name_vhost("*:443")
        self.config.save(temporary=True)

        self.assertTrue(self.config.is_name_vhost("*:443"))


    def _verify_redirect(self, config_path):
        with open(config_path, 'r') as config_fd:
            conf = config_fd.read()

        return CONFIG.REWRITE_HTTPS_ARGS[1] in conf

# def download_unpack_tests(url=CONFIG_TGZ_URL):
#     r = requests.get(url)
#     local_tgz_file = os.path.join(TESTING_DIR, 'ubuntu_2_4.tgz')
#     with open(local_tgz_file, 'w') as tgz_file:
#         tgz_file.write(r.content)

#     if tarfile.is_tarfile(local_tgz_file):
#         tar = tarfile.open(local_tgz_file)
#         tar.extractall()
#         tar.close()
