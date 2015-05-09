"""Test for letsencrypt.client.plugins.nginx.dvsni."""
import pkg_resources
import unittest
import shutil

import mock

from letsencrypt.acme import challenges

from letsencrypt.client import achallenges
from letsencrypt.client import errors
from letsencrypt.client import le_util

from letsencrypt.client.plugins.nginx.obj import Addr
from letsencrypt.client.plugins.nginx.tests import util

from letsencrypt.client.tests import acme_util


class DvsniPerformTest(util.NginxTest):
    """Test the NginxDVSNI challenge."""

    def setUp(self):
        super(DvsniPerformTest, self).setUp()

        config = util.get_nginx_configurator(
            self.config_path, self.config_dir, self.work_dir,
            self.ssl_options)

        rsa256_file = pkg_resources.resource_filename(
            "letsencrypt.acme.jose", "testdata/rsa256_key.pem")
        rsa256_pem = pkg_resources.resource_string(
            "letsencrypt.acme.jose", "testdata/rsa256_key.pem")

        auth_key = le_util.Key(rsa256_file, rsa256_pem)

        from letsencrypt.client.plugins.nginx import dvsni
        self.sni = dvsni.NginxDvsni(config)

        self.achalls = [
            achallenges.DVSNI(
                challb=acme_util.chall_to_challb(
                    challenges.DVSNI(
                        r="foo",
                        nonce="bar"
                    ), "pending"),
                domain="www.example.com", key=auth_key),
            achallenges.DVSNI(
                challb=acme_util.chall_to_challb(
                    challenges.DVSNI(
                        r="\xba\xa9\xda?<m\xaewmx\xea\xad\xadv\xf4\x02\xc9y\x80"
                          "\xe2_X\t\xe7\xc7\xa4\t\xca\xf7&\x945",
                        nonce="Y\xed\x01L\xac\x95\xf7pW\xb1\xd7"
                              "\xa1\xb2\xc5\x96\xba"
                    ), "pending"),
                domain="blah", key=auth_key),
            achallenges.DVSNI(
                challb=acme_util.chall_to_challb(
                    challenges.DVSNI(
                        r="\x8c\x8a\xbf_-f\\cw\xee\xd6\xf8/\xa5\xe3\xfd\xeb9"
                          "\xf1\xf5\xb9\xefVM\xc9w\xa4u\x9c\xe1\x87\xb4",
                        nonce="7\xbc^\xb7]>\x00\xa1\x9bOcU\x84^Z\x18"
                    ), "pending"),
                domain="www.example.org", key=auth_key)
        ]

    def tearDown(self):
        shutil.rmtree(self.temp_dir)
        shutil.rmtree(self.config_dir)
        shutil.rmtree(self.work_dir)

    def test_add_chall(self):
        self.sni.add_chall(self.achalls[0], 0)
        self.assertEqual(1, len(self.sni.achalls))
        self.assertEqual([0], self.sni.indices)

    @mock.patch("letsencrypt.client.plugins.nginx.configurator."
                "NginxConfigurator.choose_vhost")
    def test_perform(self, mock_choose):
        self.sni.add_chall(self.achalls[1])
        mock_choose.return_value = None
        result = self.sni.perform()
        self.assertTrue(result is None)

    def test_perform0(self):
        responses = self.sni.perform()
        self.assertEqual([], responses)

    @mock.patch("letsencrypt.client.plugins.nginx.configurator."
                "NginxConfigurator.save")
    def test_perform1(self, mock_save):
        self.sni.add_chall(self.achalls[0])
        mock_setup_cert = mock.MagicMock(
            return_value=challenges.DVSNIResponse(s="nginxS1"))

        # pylint: disable=protected-access
        self.sni._setup_challenge_cert = mock_setup_cert

        responses = self.sni.perform()

        mock_setup_cert.assert_called_once_with(self.achalls[0])
        self.assertEqual([challenges.DVSNIResponse(s="nginxS1")], responses)
        self.assertEqual(mock_save.call_count, 2)

        # Make sure challenge config is included in main config
        http = self.sni.configurator.parser.parsed[
            self.sni.configurator.parser.loc["root"]][-1]
        self.assertTrue(['include', self.sni.challenge_conf] in http[1])

    def test_perform2(self):
        for achall in self.achalls:
            self.sni.add_chall(achall)

        mock_setup_cert = mock.MagicMock(side_effect=[
            challenges.DVSNIResponse(s="nginxS0"),
            challenges.DVSNIResponse(s="nginxS1"),
            challenges.DVSNIResponse(s="nginxS2")])
        # pylint: disable=protected-access
        self.sni._setup_challenge_cert = mock_setup_cert

        responses = self.sni.perform()

        self.assertEqual(mock_setup_cert.call_count, 3)

        for index, achall in enumerate(self.achalls):
            self.assertEqual(
                mock_setup_cert.call_args_list[index], mock.call(achall))

        http = self.sni.configurator.parser.parsed[
            self.sni.configurator.parser.loc["root"]][-1]
        self.assertTrue(['include', self.sni.challenge_conf] in http[1])
        self.assertTrue(['server_name', 'blah'] in http[1][-2][1])

        self.assertEqual(len(responses), 3)
        for i in xrange(3):
            self.assertEqual(responses[i].s, "nginxS%d" % i)

    def test_mod_config(self):
        self.sni.add_chall(self.achalls[0])
        self.sni.add_chall(self.achalls[2])

        v_addr1 = [Addr("69.50.225.155", "9000", True, False),
                   Addr("127.0.0.1", "", False, False)]
        v_addr2 = [Addr("myhost", "", False, True)]
        ll_addr = [v_addr1, v_addr2]
        self.sni._mod_config(ll_addr)  # pylint: disable=protected-access

        self.sni.configurator.save()

        self.sni.configurator.parser.load()

        http = self.sni.configurator.parser.parsed[
            self.sni.configurator.parser.loc["root"]][-1]
        self.assertTrue(['include', self.sni.challenge_conf] in http[1])

        vhosts = self.sni.configurator.parser.get_vhosts()
        vhs = [vh for vh in vhosts if vh.filep == self.sni.challenge_conf]

        for vhost in vhs:
            if vhost.addrs == set(v_addr1):
                self.assertEqual(
                    vhost.names, set([self.achalls[0].nonce_domain]))
            else:
                self.assertEqual(vhost.addrs, set(v_addr2))
                self.assertEqual(
                    vhost.names, set([self.achalls[2].nonce_domain]))

        self.assertEqual(len(vhs), 2)

    def test_mod_config_fail(self):
        root = self.sni.configurator.parser.loc["root"]
        self.sni.configurator.parser.parsed[root] = [['include', 'foo.conf']]
        # pylint: disable=protected-access
        self.assertRaises(errors.LetsEncryptMisconfigurationError,
                          self.sni._mod_config, [])

if __name__ == "__main__":
    unittest.main()
