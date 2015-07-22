"""Test for letsencrypt_apache.configurator."""
import os
import shutil
import unittest

import mock

from acme import challenges

from letsencrypt import achallenges
from letsencrypt import errors
from letsencrypt import le_util

from letsencrypt.tests import acme_util

from letsencrypt_apache import configurator
from letsencrypt_apache import obj

from letsencrypt_apache.tests import util


class TwoVhost80Test(util.ApacheTest):
    """Test two standard well-configured HTTP vhosts."""

    def setUp(self):  # pylint: disable=arguments-differ
        super(TwoVhost80Test, self).setUp()

        self.config = util.get_apache_configurator(
            self.config_path, self.config_dir, self.work_dir)

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
            it is a problem with is_enabled.  If finding only 3, likely is_ssl

        """
        vhs = self.config.get_virtual_hosts()
        self.assertEqual(len(vhs), 4)
        found = 0

        for vhost in vhs:
            for truth in self.vh_truth:
                if vhost == truth:
                    found += 1
                    break
            else:
                raise Exception("Missed: %s" % vhost)

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

    @mock.patch("letsencrypt_apache.parser.subprocess.Popen")
    def test_enable_mod(self, mock_popen):
        mock_popen().communicate.return_value = ("Define: DUMP_RUN_CFG", "")
        mock_popen().returncode = 0

        self.config.enable_mod("ssl")
        for filename in ["ssl.conf", "ssl.load"]:
            self.assertTrue(
                os.path.isfile(os.path.join(
                    self.config.conf("server-root"), "mods-enabled", filename)))

        self.assertTrue("ssl_module" in self.config.parser.modules)
        self.assertTrue("mod_ssl.c" in self.config.parser.modules)

    @mock.patch("letsencrypt_apache.parser.subprocess.Popen")
    def test_enable_site(self, mock_popen):
        mock_popen().returncode = 0
        mock_popen().communicate.return_value = ("Define: DUMP_RUN_CFG", "")

        # Default 443 vhost
        self.assertFalse(self.vh_truth[1].enabled)
        self.config.enable_site(self.vh_truth[1])
        self.assertTrue(self.vh_truth[1].enabled)

    @mock.patch("letsencrypt_apache.parser.subprocess.Popen")
    def test_deploy_cert(self, mock_popen):
        mock_popen().returncode = 0
        mock_popen().communicate.return_value = ("Define: DUMP_RUN_CFG", "")

        # Get the default 443 vhost
        self.config.assoc["random.demo"] = self.vh_truth[1]
        self.config.deploy_cert(
            "random.demo",
            "example/cert.pem", "example/key.pem", "example/cert_chain.pem")
        self.config.save()

        # Verify ssl_module was enabled.
        self.assertTrue(self.vh_truth[1].enabled)
        self.assertTrue("ssl_module" in self.config.parser.modules)

        loc_cert = self.config.parser.find_dir(
            "sslcertificatefile", "example/cert.pem", self.vh_truth[1].path)
        loc_key = self.config.parser.find_dir(
            "sslcertificateKeyfile", "example/key.pem", self.vh_truth[1].path)
        loc_chain = self.config.parser.find_dir(
            "SSLCertificateChainFile", "example/cert_chain.pem",
            self.vh_truth[1].path)

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

    def test_deploy_cert_invalid_vhost(self):
        self.config.parser.modules.add("ssl_module")
        mock_find = mock.MagicMock()
        mock_find.return_value = []
        self.config.parser.find_dir = mock_find

        # Get the default 443 vhost
        self.config.assoc["random.demo"] = self.vh_truth[1]
        self.assertRaises(
            errors.PluginError, self.config.deploy_cert, "random.demo",
            "example/cert.pem", "example/key.pem", "example/cert_chain.pem")

    def test_is_name_vhost(self):
        addr = obj.Addr.fromstring("*:80")
        self.assertTrue(self.config.is_name_vhost(addr))
        self.config.version = (2, 2)
        self.assertFalse(self.config.is_name_vhost(addr))

    def test_add_name_vhost(self):
        self.config.add_name_vhost(obj.Addr.fromstring("*:443"))
        self.assertTrue(self.config.parser.find_dir(
            "NameVirtualHost", "*:443"))

    def test_prepare_server_https(self):
        self.config.parser.modules.add("ssl_module")
        mock_find = mock.Mock()
        mock_add_dir = mock.Mock()
        mock_find.return_value = []

        # This will test the Add listen
        self.config.parser.find_dir = mock_find
        self.config.parser.add_dir_to_ifmodssl = mock_add_dir

        self.config.prepare_server_https("443")
        self.assertTrue(mock_add_dir.called)

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
        self.assertEqual(ssl_vhost.name, "encryption-example.demo")
        self.assertTrue(ssl_vhost.ssl)
        self.assertFalse(ssl_vhost.enabled)

        self.assertTrue(self.config.parser.find_dir(
            "SSLCertificateFile", None, ssl_vhost.path, False))
        self.assertTrue(self.config.parser.find_dir(
            "SSLCertificateKeyFile", None, ssl_vhost.path, False))

        self.assertEqual(self.config.is_name_vhost(self.vh_truth[0]),
                         self.config.is_name_vhost(ssl_vhost))

        self.assertEqual(len(self.config.vhosts), 5)

    @mock.patch("letsencrypt_apache.configurator.dvsni.ApacheDvsni.perform")
    @mock.patch("letsencrypt_apache.configurator.ApacheConfigurator.restart")
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

    @mock.patch("letsencrypt_apache.configurator.subprocess.Popen")
    def test_get_version(self, mock_popen):
        mock_popen().communicate.return_value = (
            "Server Version: Apache/2.4.2 (Debian)", "")
        self.assertEqual(self.config.get_version(), (2, 4, 2))

        mock_popen().communicate.return_value = (
            "Server Version: Apache/2 (Linux)", "")
        self.assertEqual(self.config.get_version(), (2,))

        mock_popen().communicate.return_value = (
            "Server Version: Apache (Debian)", "")
        self.assertRaises(errors.PluginError, self.config.get_version)

        mock_popen().communicate.return_value = (
            "Server Version: Apache/2.3{0} Apache/2.4.7".format(os.linesep), "")
        self.assertRaises(errors.PluginError, self.config.get_version)

        mock_popen.side_effect = OSError("Can't find program")
        self.assertRaises(errors.PluginError, self.config.get_version)


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
