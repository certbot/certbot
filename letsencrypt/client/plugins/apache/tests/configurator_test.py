"""Test for letsencrypt.client.plugins.apache.configurator."""
import os
import re
import shutil
import unittest

import mock

from letsencrypt.acme import challenges

from letsencrypt.client import achallenges
from letsencrypt.client import errors
from letsencrypt.client import le_util

from letsencrypt.client.plugins.apache import configurator
from letsencrypt.client.plugins.apache import obj
from letsencrypt.client.plugins.apache import parser

from letsencrypt.client.plugins.apache.tests import util

from letsencrypt.client.tests import acme_util


class TwoVhost80Test(util.ApacheTest):
    """Test two standard well configured HTTP vhosts."""

    def setUp(self):
        super(TwoVhost80Test, self).setUp()

        with mock.patch("letsencrypt.client.plugins.apache.configurator."
                        "mod_loaded") as mock_load:
            mock_load.return_value = True
            self.config = util.get_apache_configurator(
                self.config_path, self.config_dir, self.work_dir,
                self.ssl_options)

        self.vh_truth = util.get_vh_truth(
            self.temp_dir, "debian_apache_2_4/two_vhost_80")

    def tearDown(self):
        shutil.rmtree(self.temp_dir)
        shutil.rmtree(self.config_dir)
        shutil.rmtree(self.work_dir)

    def test_get_all_names(self):
        names = self.config.get_all_names()
        self.assertEqual(names, set(
            ["letsencrypt.demo", "encryption-example.demo", "ip-172-30-0-17"]))

    def test_get_virtual_hosts(self):
        """Make sure all vhosts are being properly found.

        .. note:: If test fails, only finding 1 Vhost... it is likely that
            it is a problem with is_enabled.

        """
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
        """Test if site is enabled.

        .. note:: This test currently fails for hard links
            (which may happen if you move dirs incorrectly)
        .. warning:: This test does not work when running using the
            unittest.main() function. It incorrectly copies symlinks.

        """
        self.assertTrue(self.config.is_site_enabled(self.vh_truth[0].filep))
        self.assertFalse(self.config.is_site_enabled(self.vh_truth[1].filep))
        self.assertTrue(self.config.is_site_enabled(self.vh_truth[2].filep))
        self.assertTrue(self.config.is_site_enabled(self.vh_truth[3].filep))

    def test_deploy_cert(self):
        # Get the default 443 vhost
        self.config.assoc["random.demo"] = self.vh_truth[1]
        self.config.deploy_cert(
            "random.demo",
            "example/cert.pem", "example/key.pem", "example/cert_chain.pem")
        self.config.save()

        loc_cert = self.config.parser.find_dir(
            parser.case_i("sslcertificatefile"),
            re.escape("example/cert.pem"), self.vh_truth[1].path)
        loc_key = self.config.parser.find_dir(
            parser.case_i("sslcertificateKeyfile"),
            re.escape("example/key.pem"), self.vh_truth[1].path)
        loc_chain = self.config.parser.find_dir(
            parser.case_i("SSLCertificateChainFile"),
            re.escape("example/cert_chain.pem"), self.vh_truth[1].path)

        # Verify one directive was found in the correct file
        self.assertEqual(len(loc_cert), 1)
        self.assertEqual(configurator.get_file_path(loc_cert[0]),
                         self.vh_truth[1].filep)

        self.assertEqual(len(loc_key), 1)
        self.assertEqual(configurator.get_file_path(loc_key[0]),
                         self.vh_truth[1].filep)

        self.assertEqual(len(loc_chain), 1)
        self.assertEqual(configurator.get_file_path(loc_chain[0]),
                         self.vh_truth[1].filep)

    def test_is_name_vhost(self):
        addr = obj.Addr.fromstring("*:80")
        self.assertTrue(self.config.is_name_vhost(addr))
        self.config.version = (2, 2)
        self.assertFalse(self.config.is_name_vhost(addr))

    def test_add_name_vhost(self):
        self.config.add_name_vhost("*:443")
        self.assertTrue(self.config.parser.find_dir(
            "NameVirtualHost", re.escape("*:443")))

    def test_make_vhost_ssl(self):
        ssl_vhost = self.config.make_vhost_ssl(self.vh_truth[0])

        self.assertEqual(
            ssl_vhost.filep,
            os.path.join(self.config_path, "sites-available",
                         "encryption-example-le-ssl.conf"))

        self.assertEqual(ssl_vhost.path,
                         "/files" + ssl_vhost.filep + "/IfModule/VirtualHost")
        self.assertEqual(len(ssl_vhost.addrs), 1)
        self.assertEqual(set([obj.Addr.fromstring("*:443")]), ssl_vhost.addrs)
        self.assertEqual(ssl_vhost.names, set(["encryption-example.demo"]))
        self.assertTrue(ssl_vhost.ssl)
        self.assertFalse(ssl_vhost.enabled)

        self.assertTrue(self.config.parser.find_dir(
            "SSLCertificateFile", None, ssl_vhost.path))
        self.assertTrue(self.config.parser.find_dir(
            "SSLCertificateKeyFile", None, ssl_vhost.path))
        self.assertTrue(self.config.parser.find_dir(
            "Include", self.ssl_options, ssl_vhost.path))

        self.assertEqual(self.config.is_name_vhost(self.vh_truth[0]),
                         self.config.is_name_vhost(ssl_vhost))

        self.assertEqual(len(self.config.vhosts), 5)

    @mock.patch("letsencrypt.client.plugins.apache.configurator."
                "dvsni.ApacheDvsni.perform")
    @mock.patch("letsencrypt.client.plugins.apache.configurator."
                "ApacheConfigurator.restart")
    def test_perform(self, mock_restart, mock_dvsni_perform):
        # Only tests functionality specific to configurator.perform
        # Note: As more challenges are offered this will have to be expanded
        auth_key = le_util.Key(self.rsa256_file, self.rsa256_pem)
        achall1 = achallenges.DVSNI(
            challb=acme_util.chall_to_challb(
                challenges.DVSNI(
                    r="jIq_Xy1mXGN37tb4L6Xj_es58fW571ZNyXekdZzhh7Q",
                    nonce="37bc5eb75d3e00a19b4f6355845e5a18"),
                "pending"),
            domain="encryption-example.demo", key=auth_key)
        achall2 = achallenges.DVSNI(
            challb=acme_util.chall_to_challb(
                challenges.DVSNI(
                    r="uqnaPzxtrndteOqtrXb0Asl5gOJfWAnnx6QJyvcmlDU",
                    nonce="59ed014cac95f77057b1d7a1b2c596ba"),
                "pending"),
            domain="letsencrypt.demo", key=auth_key)

        dvsni_ret_val = [
            challenges.DVSNIResponse(s="randomS1"),
            challenges.DVSNIResponse(s="randomS2"),
        ]

        mock_dvsni_perform.return_value = dvsni_ret_val
        responses = self.config.perform([achall1, achall2])

        self.assertEqual(mock_dvsni_perform.call_count, 1)
        self.assertEqual(responses, dvsni_ret_val)

        self.assertEqual(mock_restart.call_count, 1)

    @mock.patch("letsencrypt.client.plugins.apache.configurator."
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
            "Server Version: Apache/2.3{0} Apache/2.4.7".format(os.linesep), "")
        self.assertRaises(
            errors.LetsEncryptConfiguratorError, self.config.get_version)

        mock_popen.side_effect = OSError("Can't find program")
        self.assertRaises(
            errors.LetsEncryptConfiguratorError, self.config.get_version)


if __name__ == "__main__":
    unittest.main()
