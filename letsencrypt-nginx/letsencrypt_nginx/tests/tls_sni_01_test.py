"""Tests for letsencrypt_nginx.tls_sni_01"""
import unittest
import shutil

import mock

from acme import challenges

from letsencrypt import achallenges
from letsencrypt import errors

from letsencrypt.plugins import common_test
from letsencrypt.tests import acme_util

from letsencrypt_nginx import obj
from letsencrypt_nginx.tests import util


class TlsSniPerformTest(util.NginxTest):
    """Test the NginxTlsSni01 challenge."""

    account_key = common_test.TLSSNI01Test.auth_key
    dot_com_achall = achallenges.KeyAuthorizationAnnotatedChallenge(
        challb=acme_util.chall_to_challb(
            challenges.TLSSNI01(token="kNdwjwOeX0I_A8DXt9Msmg"), "pending"),
            domain="www.example.com",
            account_key=account_key)

    dot_org_achall = achallenges.KeyAuthorizationAnnotatedChallenge(
        challb=acme_util.chall_to_challb(
            challenges.TLSSNI01(
                token="\x8c\x8a\xbf_-f\\cw\xee\xd6\xf8/\xa5\xe3\xfd"
                    "\xeb9\xf1\xf5\xb9\xefVM\xc9w\xa4u\x9c\xe1\x87\xb4"), "pending"),
            domain="www.example.org",
            account_key=account_key)
    vhost_not_configured_achall = achallenges.KeyAuthorizationAnnotatedChallenge(
        challb=acme_util.chall_to_challb(
            challenges.TLSSNI01(
                token="\xba\xa9\xda?<m\xaewmx\xea\xad\xadv\xf4\x02\xc9y"
                    "\x80\xe2_X\t\xe7\xc7\xa4\t\xca\xf7&\x945"), "pending"),
            domain="vhost_not_configured",
            account_key=account_key)

    def setUp(self):
        super(TlsSniPerformTest, self).setUp()

        config = util.get_nginx_configurator(
            self.config_path, self.config_dir, self.work_dir)

        from letsencrypt_nginx import tls_sni_01
        self.sni = tls_sni_01.NginxTlsSni01(config)

    def tearDown(self):
        shutil.rmtree(self.temp_dir)
        shutil.rmtree(self.config_dir)
        shutil.rmtree(self.work_dir)

    @mock.patch("letsencrypt_nginx.configurator"
                ".NginxConfigurator.choose_vhost")
    def test_perform_returns_none_when_vhost_not_found(self, mock_choose):
        self.sni.add_chall(self.vhost_not_configured_achall)
        mock_choose.return_value = None
        result = self.sni.perform()
        self.assertTrue(result is None)

    def test_perform_returns_empty_when_does_not_have_chall(self):
        responses = self.sni.perform()
        self.assertEqual([], responses)

    @mock.patch("letsencrypt_nginx.configurator.NginxConfigurator.save")
    def test_perform_single_domain(self, mock_save):
        self.sni.add_chall(self.dot_com_achall)
        response = self.dot_com_achall.response(self.account_key)
        mock_setup_cert = mock.MagicMock(return_value=response)

        # pylint: disable=protected-access
        self.sni._setup_challenge_cert = mock_setup_cert

        responses = self.sni.perform()

        mock_setup_cert.assert_called_once_with(self.dot_com_achall)
        self.assertEqual([response], responses)
        self.assertEqual(mock_save.call_count, 2)

        # Make sure challenge config is included in main config
        http = self.sni.configurator.parser.parsed[
            self.sni.configurator.parser.loc["root"]][-1]
        self.assertTrue(
            util.contains_at_depth(http, ['include', self.sni.challenge_conf], 1))

    def test_perform_multiple_domain(self):
        acme_responses = []
        self.sni.add_chall(self.dot_com_achall)
        acme_responses.append(self.dot_com_achall.response(self.account_key))
        self.sni.add_chall(self.dot_org_achall)
        acme_responses.append(self.dot_org_achall.response(self.account_key))

        mock_setup_cert = mock.MagicMock(side_effect=acme_responses)
        # pylint: disable=protected-access
        self.sni._setup_challenge_cert = mock_setup_cert

        sni_responses = self.sni.perform()
        self.assertEqual(len(sni_responses), 2)
        self.assertEqual(sni_responses, acme_responses)

        self.assertEqual(mock_setup_cert.call_count, 2)
        mock_setup_cert.assert_any_call(self.dot_com_achall)
        mock_setup_cert.assert_any_call(self.dot_org_achall)

        http = self.sni.configurator.parser.parsed[
            self.sni.configurator.parser.loc["root"]][-1]
        self.assertTrue(
            util.contains_at_depth(http, ['include', self.sni.challenge_conf], 1))

    def test_mod_config(self):
        self.sni.add_chall(self.dot_com_achall)
        self.sni.add_chall(self.dot_org_achall)

        v_addr1 = [obj.Addr("69.50.225.155", "9000", True, False),
                   obj.Addr("127.0.0.1", "", False, False)]
        v_addr2 = [obj.Addr("myhost", "", False, True)]
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
                response = self.dot_com_achall.response(self.account_key)
            else:
                response = self.dot_org_achall.response(self.account_key)
                self.assertEqual(vhost.addrs, set(v_addr2))
            self.assertEqual(vhost.names, set([response.z_domain]))

        self.assertEqual(len(vhs), 2)

    def test_mod_config_fail(self):
        root = self.sni.configurator.parser.loc["root"]
        self.sni.configurator.parser.parsed[root] = [['include', 'foo.conf']]
        # pylint: disable=protected-access
        self.assertRaises(
            errors.MisconfigurationError, self.sni._mod_config, [])

if __name__ == "__main__":
    unittest.main()  # pragma: no cover
