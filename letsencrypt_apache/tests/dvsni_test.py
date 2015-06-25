"""Test for letsencrypt_apache.dvsni."""
import unittest
import shutil

import mock

from acme import challenges

from letsencrypt.plugins import common
from letsencrypt.plugins import common_test

from letsencrypt_apache.tests import util


class DvsniPerformTest(util.ApacheTest):
    """Test the ApacheDVSNI challenge."""

    achalls = common_test.DvsniTest.achalls

    def setUp(self):
        super(DvsniPerformTest, self).setUp()

        with mock.patch("letsencrypt_apache.configurator."
                        "mod_loaded") as mock_load:
            mock_load.return_value = True
            config = util.get_apache_configurator(
                self.config_path, self.config_dir, self.work_dir)

        from letsencrypt_apache import dvsni
        self.sni = dvsni.ApacheDvsni(config)

    def tearDown(self):
        shutil.rmtree(self.temp_dir)
        shutil.rmtree(self.config_dir)
        shutil.rmtree(self.work_dir)

    def test_perform0(self):
        resp = self.sni.perform()
        self.assertEqual(len(resp), 0)

    def test_perform1(self):
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
                "Include", self.sni.challenge_conf)),
            1)
        self.assertEqual(len(responses), 1)
        self.assertEqual(responses[0].s, "randomS1")

    def test_perform2(self):
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
        v_addr1 = [common.Addr(("1.2.3.4", "443")),
                   common.Addr(("5.6.7.8", "443"))]
        v_addr2 = [common.Addr(("127.0.0.1", "443"))]
        ll_addr = []
        ll_addr.append(v_addr1)
        ll_addr.append(v_addr2)
        self.sni._mod_config(ll_addr)  # pylint: disable=protected-access
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
            if vhost.addrs == set(v_addr1):
                self.assertEqual(
                    vhost.names,
                    set([self.achalls[0].nonce_domain]))
            else:
                self.assertEqual(vhost.addrs, set(v_addr2))
                self.assertEqual(
                    vhost.names,
                    set([self.achalls[1].nonce_domain]))


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
