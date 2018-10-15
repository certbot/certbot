"""Tests for certbot_nginx.http_01"""
import unittest
import shutil

import mock
import six

from acme import challenges

from certbot import achallenges

from certbot.plugins import common_test
from certbot.tests import acme_util

from certbot_nginx.obj import Addr
from certbot_nginx.tests import util


class HttpPerformTest(util.NginxTest):
    """Test the NginxHttp01 challenge."""

    account_key = common_test.AUTH_KEY
    achalls = [
        achallenges.KeyAuthorizationAnnotatedChallenge(
            challb=acme_util.chall_to_challb(
                challenges.HTTP01(token=b"kNdwjwOeX0I_A8DXt9Msmg"), "pending"),
            domain="www.example.com", account_key=account_key),
        achallenges.KeyAuthorizationAnnotatedChallenge(
            challb=acme_util.chall_to_challb(
                challenges.HTTP01(
                    token=b"\xba\xa9\xda?<m\xaewmx\xea\xad\xadv\xf4\x02\xc9y"
                          b"\x80\xe2_X\t\xe7\xc7\xa4\t\xca\xf7&\x945"
                ), "pending"),
            domain="ipv6.com", account_key=account_key),
        achallenges.KeyAuthorizationAnnotatedChallenge(
            challb=acme_util.chall_to_challb(
                challenges.HTTP01(
                    token=b"\x8c\x8a\xbf_-f\\cw\xee\xd6\xf8/\xa5\xe3\xfd"
                          b"\xeb9\xf1\xf5\xb9\xefVM\xc9w\xa4u\x9c\xe1\x87\xb4"
                ), "pending"),
            domain="www.example.org", account_key=account_key),
        achallenges.KeyAuthorizationAnnotatedChallenge(
            challb=acme_util.chall_to_challb(
                challenges.HTTP01(token=b"kNdwjxOeX0I_A8DXt9Msmg"), "pending"),
            domain="migration.com", account_key=account_key),
    ]

    def setUp(self):
        super(HttpPerformTest, self).setUp()

        config = util.get_nginx_configurator(
            self.config_path, self.config_dir, self.work_dir, self.logs_dir)

        from certbot_nginx import http_01
        self.http01 = http_01.NginxHttp01(config)

    def tearDown(self):
        shutil.rmtree(self.temp_dir)
        shutil.rmtree(self.config_dir)
        shutil.rmtree(self.work_dir)

    def test_perform0(self):
        responses = self.http01.perform()
        self.assertEqual([], responses)

    @mock.patch("certbot_nginx.configurator.NginxConfigurator.save")
    def test_perform1(self, mock_save):
        self.http01.add_chall(self.achalls[0])
        response = self.achalls[0].response(self.account_key)

        responses = self.http01.perform()

        self.assertEqual([response], responses)
        self.assertEqual(mock_save.call_count, 1)

    def test_perform2(self):
        acme_responses = []
        for achall in self.achalls:
            self.http01.add_chall(achall)
            acme_responses.append(achall.response(self.account_key))

        sni_responses = self.http01.perform()

        self.assertEqual(len(sni_responses), 4)
        for i in six.moves.range(4):
            self.assertEqual(sni_responses[i], acme_responses[i])

    def test_mod_config(self):
        self.http01.add_chall(self.achalls[0])
        self.http01.add_chall(self.achalls[2])

        self.http01._mod_config()  # pylint: disable=protected-access

        self.http01.configurator.save()

        self.http01.configurator.parser.load()

        # vhosts = self.http01.configurator.parser.get_vhosts()

        # for vhost in vhosts:
        #     pass
            # if the name matches
            # check that the location block is in there and is correct

            # if vhost.addrs == set(v_addr1):
            #     response = self.achalls[0].response(self.account_key)
            # else:
            #     response = self.achalls[2].response(self.account_key)
            #     self.assertEqual(vhost.addrs, set(v_addr2_print))
            # self.assertEqual(vhost.names, set([response.z_domain.decode('ascii')]))

    @mock.patch("certbot_nginx.configurator.NginxConfigurator.ipv6_info")
    def test_default_listen_addresses_no_memoization(self, ipv6_info):
        # pylint: disable=protected-access
        ipv6_info.return_value = (True, True)
        self.http01._default_listen_addresses()
        self.assertEqual(ipv6_info.call_count, 1)
        ipv6_info.return_value = (False, False)
        self.http01._default_listen_addresses()
        self.assertEqual(ipv6_info.call_count, 2)

    @mock.patch("certbot_nginx.configurator.NginxConfigurator.ipv6_info")
    def test_default_listen_addresses_t_t(self, ipv6_info):
        # pylint: disable=protected-access
        ipv6_info.return_value = (True, True)
        addrs = self.http01._default_listen_addresses()
        http_addr = Addr.fromstring("80")
        http_ipv6_addr = Addr.fromstring("[::]:80")
        self.assertEqual(addrs, [http_addr, http_ipv6_addr])

    @mock.patch("certbot_nginx.configurator.NginxConfigurator.ipv6_info")
    def test_default_listen_addresses_t_f(self, ipv6_info):
        # pylint: disable=protected-access
        ipv6_info.return_value = (True, False)
        addrs = self.http01._default_listen_addresses()
        http_addr = Addr.fromstring("80")
        http_ipv6_addr = Addr.fromstring("[::]:80 ipv6only=on")
        self.assertEqual(addrs, [http_addr, http_ipv6_addr])

    @mock.patch("certbot_nginx.configurator.NginxConfigurator.ipv6_info")
    def test_default_listen_addresses_f_f(self, ipv6_info):
        # pylint: disable=protected-access
        ipv6_info.return_value = (False, False)
        addrs = self.http01._default_listen_addresses()
        http_addr = Addr.fromstring("80")
        self.assertEqual(addrs, [http_addr])

if __name__ == "__main__":
    unittest.main()  # pragma: no cover
