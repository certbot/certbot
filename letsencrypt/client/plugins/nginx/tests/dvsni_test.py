"""Test for letsencrypt.client.nginx.dvsni."""
import pkg_resources
import unittest
import shutil

import mock

from letsencrypt.acme import challenges

from letsencrypt.client import achallenges
from letsencrypt.client import le_util

from letsencrypt.client.nginx.obj import Addr

from letsencrypt.client.tests.nginx import util


class DvsniPerformTest(util.NginxTest):
    """Test the NginxDVSNI challenge."""

    def setUp(self):
        super(DvsniPerformTest, self).setUp()

        with mock.patch("letsencrypt.client.nginx.configurator."
                        "mod_loaded") as mock_load:
            mock_load.return_value = True
            config = util.get_nginx_configurator(
                self.config_path, self.config_dir, self.work_dir,
                self.ssl_options)

        from letsencrypt.client.nginx import dvsni
        self.sni = dvsni.NginxDvsni(config)

        rsa256_file = pkg_resources.resource_filename(
            "letsencrypt.client.tests", 'testdata/rsa256_key.pem')
        rsa256_pem = pkg_resources.resource_string(
            "letsencrypt.client.tests", 'testdata/rsa256_key.pem')

        auth_key = le_util.Key(rsa256_file, rsa256_pem)
        self.achalls = [
            achallenges.DVSNI(
                chall=challenges.DVSNI(
                    r="\x8c\x8a\xbf_-f\\cw\xee\xd6\xf8/\xa5\xe3\xfd\xeb9\xf1"
                      "\xf5\xb9\xefVM\xc9w\xa4u\x9c\xe1\x87\xb4",
                    nonce="7\xbc^\xb7]>\x00\xa1\x9bOcU\x84^Z\x18",
                ), domain="encryption-example.demo", key=auth_key),
            achallenges.DVSNI(
                chall=challenges.DVSNI(
                    r="\xba\xa9\xda?<m\xaewmx\xea\xad\xadv\xf4\x02\xc9y\x80"
                      "\xe2_X\t\xe7\xc7\xa4\t\xca\xf7&\x945",
                    nonce="Y\xed\x01L\xac\x95\xf7pW\xb1\xd7"
                          "\xa1\xb2\xc5\x96\xba",
                ), domain="letsencrypt.demo", key=auth_key),
        ]

    def tearDown(self):
        shutil.rmtree(self.temp_dir)
        shutil.rmtree(self.config_dir)
        shutil.rmtree(self.work_dir)

    def test_perform0(self):
        resp = self.sni.perform()
        self.assertEqual(len(resp), 0)

    def test_setup_challenge_cert(self):
        # This is a helper function that can be used for handling
        # open context managers more elegantly. It avoids dealing with
        # __enter__ and __exit__ calls.
        # http://www.voidspace.org.uk/python/mock/helpers.html#mock.mock_open
        m_open = mock.mock_open()

        response = challenges.DVSNIResponse(s="randomS1")
        achall = mock.MagicMock(nonce=self.achalls[0].nonce,
                                nonce_domain=self.achalls[0].nonce_domain)
        achall.gen_cert_and_response.return_value = ("pem", response)

        with mock.patch("letsencrypt.client.nginx.dvsni.open",
                        m_open, create=True):
            # pylint: disable=protected-access
            self.assertEqual(response, self.sni._setup_challenge_cert(
                achall, "randomS1"))

            self.assertTrue(m_open.called)
            self.assertEqual(
                m_open.call_args[0], (self.sni.get_cert_file(achall), 'w'))
            self.assertEqual(m_open().write.call_args[0][0], "pem")

    def test_perform1(self):
        achall = self.achalls[0]
        self.sni.add_chall(achall)
        mock_setup_cert = mock.MagicMock(
            return_value=challenges.DVSNIResponse(s="randomS1"))
        # pylint: disable=protected-access
        self.sni._setup_challenge_cert = mock_setup_cert

        responses = self.sni.perform()

        mock_setup_cert.assert_called_once_with(achall)

        # Check to make sure challenge config path is included in nginx config.
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
        v_addr1 = [Addr(("1.2.3.4", "443")), Addr(("5.6.7.8", "443"))]
        v_addr2 = [Addr(("127.0.0.1", "443"))]
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


if __name__ == '__main__':
    unittest.main()
