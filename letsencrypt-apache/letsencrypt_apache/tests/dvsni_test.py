"""Test for letsencrypt_apache.dvsni."""
import unittest
import shutil

import mock

from acme import challenges

from letsencrypt.plugins import common_test

from letsencrypt_apache import obj
from letsencrypt_apache.tests import util


class DvsniPerformTest(util.ApacheTest):
    """Test the ApacheDVSNI challenge."""

    achalls = common_test.DvsniTest.achalls

    def setUp(self):  # pylint: disable=arguments-differ
        super(DvsniPerformTest, self).setUp()

        config = util.get_apache_configurator(
            self.config_path, self.config_dir, self.work_dir)
        config.config.dvsni_port = 443

        from letsencrypt_apache import dvsni
        self.sni = dvsni.ApacheDvsni(config)

    def tearDown(self):
        shutil.rmtree(self.temp_dir)
        shutil.rmtree(self.config_dir)
        shutil.rmtree(self.work_dir)

    def test_perform0(self):
        resp = self.sni.perform()
        self.assertEqual(len(resp), 0)

    @mock.patch("letsencrypt_apache.parser.subprocess.Popen")
    def test_perform1(self, mock_popen):
        mock_popen().communicate.return_value = ("Define: DUMP_RUN_CFG", "")
        mock_popen().returncode = 0

        achall = self.achalls[0]
        self.sni.add_chall(achall)
        mock_setup_cert = mock.MagicMock(
            return_value=challenges.DVSNIResponse(s="randomS1"))
        # pylint: disable=protected-access
        self.sni._setup_challenge_cert = mock_setup_cert

        responses = self.sni.perform()

        mock_setup_cert.assert_called_once_with(achall)

        # Check to make sure challenge config path is included in apache config.
        self.assertEqual(
            len(self.sni.configurator.parser.find_dir(
                "Include", self.sni.challenge_conf)), 1)
        self.assertEqual(len(responses), 1)
        self.assertEqual(responses[0].s, "randomS1")

    def test_perform2(self):
        # Avoid load module
        self.sni.configurator.parser.modules.add("ssl_module")

        for achall in self.achalls:
            self.sni.add_chall(achall)

        mock_setup_cert = mock.MagicMock(side_effect=[
            challenges.DVSNIResponse(s="randomS0"),
            challenges.DVSNIResponse(s="randomS1")])
        # pylint: disable=protected-access
        self.sni._setup_challenge_cert = mock_setup_cert

        responses = self.sni.perform()

        self.assertEqual(mock_setup_cert.call_count, 2)

        # Make sure calls made to mocked function were correct
        self.assertEqual(
            mock_setup_cert.call_args_list[0], mock.call(self.achalls[0]))
        self.assertEqual(
            mock_setup_cert.call_args_list[1], mock.call(self.achalls[1]))

        self.assertEqual(
            len(self.sni.configurator.parser.find_dir(
                "Include", self.sni.challenge_conf)),
            1)
        self.assertEqual(len(responses), 2)
        for i in xrange(2):
            self.assertEqual(responses[i].s, "randomS%d" % i)

    def test_mod_config(self):
        for achall in self.achalls:
            self.sni.add_chall(achall)

        self.sni._mod_config()  # pylint: disable=protected-access
        self.sni.configurator.save()

        self.sni.configurator.parser.find_dir(
            "Include", self.sni.challenge_conf)
        vh_match = self.sni.configurator.aug.match(
            "/files" + self.sni.challenge_conf + "//VirtualHost")

        vhs = []
        for match in vh_match:
            # pylint: disable=protected-access
            vhs.append(self.sni.configurator._create_vhost(match))
        self.assertEqual(len(vhs), 2)
        for vhost in vhs:
            self.assertEqual(vhost.addrs, set([obj.Addr.fromstring("*:443")]))
            names = vhost.get_names()
            self.assertTrue(
                names == set([self.achalls[0].nonce_domain]) or
                names == set([self.achalls[1].nonce_domain]))

    def test_get_dvsni_addrs_default(self):
        self.sni.configurator.choose_vhost = mock.Mock(
            return_value=obj.VirtualHost(
                "path", "aug_path", set([obj.Addr.fromstring("_default_:443")]),
                False, False)
        )

        self.assertEqual(
            set([obj.Addr.fromstring("*:443")]),
            self.sni.get_dvsni_addrs(self.achalls[0]))


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
