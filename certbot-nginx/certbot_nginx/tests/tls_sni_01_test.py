"""Tests for certbot_nginx.tls_sni_01"""
import unittest
import shutil

import mock
import six

from acme import challenges

from certbot import achallenges
from certbot import errors

from certbot.plugins import common_test
from certbot.tests import acme_util

from certbot_nginx import obj
from certbot_nginx.tests import util


class TlsSniPerformTest(util.NginxTest):
    """Test the NginxTlsSni01 challenge."""

    account_key = common_test.AUTH_KEY
    achalls = [
        achallenges.KeyAuthorizationAnnotatedChallenge(
            challb=acme_util.chall_to_challb(
                challenges.TLSSNI01(token=b"kNdwjwOeX0I_A8DXt9Msmg"), "pending"),
            domain="www.example.com", account_key=account_key),
        achallenges.KeyAuthorizationAnnotatedChallenge(
            challb=acme_util.chall_to_challb(
                challenges.TLSSNI01(
                    token=b"\xba\xa9\xda?<m\xaewmx\xea\xad\xadv\xf4\x02\xc9y"
                          b"\x80\xe2_X\t\xe7\xc7\xa4\t\xca\xf7&\x945"
                ), "pending"),
            domain="another.alias", account_key=account_key),
        achallenges.KeyAuthorizationAnnotatedChallenge(
            challb=acme_util.chall_to_challb(
                challenges.TLSSNI01(
                    token=b"\x8c\x8a\xbf_-f\\cw\xee\xd6\xf8/\xa5\xe3\xfd"
                          b"\xeb9\xf1\xf5\xb9\xefVM\xc9w\xa4u\x9c\xe1\x87\xb4"
                ), "pending"),
            domain="www.example.org", account_key=account_key),
        achallenges.KeyAuthorizationAnnotatedChallenge(
            challb=acme_util.chall_to_challb(
                challenges.TLSSNI01(token=b"kNdwjxOeX0I_A8DXt9Msmg"), "pending"),
            domain="sslon.com", account_key=account_key),
    ]

    def setUp(self):
        super(TlsSniPerformTest, self).setUp()

        config = util.get_nginx_configurator(
            self.config_path, self.config_dir, self.work_dir, self.logs_dir)

        from certbot_nginx import tls_sni_01
        self.sni = tls_sni_01.NginxTlsSni01(config)

    def tearDown(self):
        shutil.rmtree(self.temp_dir)
        shutil.rmtree(self.config_dir)
        shutil.rmtree(self.work_dir)

    @mock.patch("certbot_nginx.configurator"
                ".NginxConfigurator.choose_vhosts")
    def test_perform(self, mock_choose):
        self.sni.add_chall(self.achalls[1])
        mock_choose.return_value = []
        result = self.sni.perform()
        self.assertFalse(result is None)

    def test_perform0(self):
        responses = self.sni.perform()
        self.assertEqual([], responses)

    @mock.patch("certbot_nginx.configurator.NginxConfigurator.save")
    def test_perform1(self, mock_save):
        self.sni.add_chall(self.achalls[0])
        response = self.achalls[0].response(self.account_key)
        mock_setup_cert = mock.MagicMock(return_value=response)

        # pylint: disable=protected-access
        self.sni._setup_challenge_cert = mock_setup_cert

        responses = self.sni.perform()

        mock_setup_cert.assert_called_once_with(self.achalls[0])
        self.assertEqual([response], responses)
        self.assertEqual(mock_save.call_count, 1)

        # Make sure challenge config is included in main config
        http = self.sni.configurator.parser.parsed[
            self.sni.configurator.parser.config_root][-1]
        self.assertTrue(
            util.contains_at_depth(http, ['include', self.sni.challenge_conf], 1))

    def test_perform2(self):
        acme_responses = []
        for achall in self.achalls:
            self.sni.add_chall(achall)
            acme_responses.append(achall.response(self.account_key))

        mock_setup_cert = mock.MagicMock(side_effect=acme_responses)
        # pylint: disable=protected-access
        self.sni._setup_challenge_cert = mock_setup_cert

        sni_responses = self.sni.perform()

        self.assertEqual(mock_setup_cert.call_count, 4)

        for index, achall in enumerate(self.achalls):
            self.assertEqual(
                mock_setup_cert.call_args_list[index], mock.call(achall))

        http = self.sni.configurator.parser.parsed[
            self.sni.configurator.parser.config_root][-1]
        self.assertTrue(['include', self.sni.challenge_conf] in http[1])
        self.assertFalse(
            util.contains_at_depth(http, ['server_name', 'another.alias'], 3))

        self.assertEqual(len(sni_responses), 4)
        for i in six.moves.range(4):
            self.assertEqual(sni_responses[i], acme_responses[i])

    def test_mod_config(self):
        self.sni.add_chall(self.achalls[0])
        self.sni.add_chall(self.achalls[2])

        v_addr1 = [obj.Addr("69.50.225.155", "9000", True, False, False, False),
                   obj.Addr("127.0.0.1", "", False, False, False, False)]
        v_addr2 = [obj.Addr("myhost", "", False, True, False, False)]
        v_addr2_print = [obj.Addr("myhost", "", False, False, False, False)]
        ll_addr = [v_addr1, v_addr2]
        self.sni._mod_config(ll_addr)  # pylint: disable=protected-access

        self.sni.configurator.save()

        self.sni.configurator.parser.load()

        http = self.sni.configurator.parser.parsed[
            self.sni.configurator.parser.config_root][-1]
        self.assertTrue(['include', self.sni.challenge_conf] in http[1])

        vhosts = self.sni.configurator.parser.get_vhosts()
        vhs = [vh for vh in vhosts if vh.filep == self.sni.challenge_conf]

        for vhost in vhs:
            if vhost.addrs == set(v_addr1):
                response = self.achalls[0].response(self.account_key)
            else:
                response = self.achalls[2].response(self.account_key)
                self.assertEqual(vhost.addrs, set(v_addr2_print))
            self.assertEqual(vhost.names, set([response.z_domain.decode('ascii')]))

        self.assertEqual(len(vhs), 2)

    def test_mod_config_fail(self):
        root = self.sni.configurator.parser.config_root
        self.sni.configurator.parser.parsed[root] = [['include', 'foo.conf']]
        # pylint: disable=protected-access
        self.assertRaises(
            errors.MisconfigurationError, self.sni._mod_config, [])

if __name__ == "__main__":
    unittest.main()  # pragma: no cover
