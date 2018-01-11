"""Tests for certbot_nginx.challenges"""
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

class ChallengePerformTest(object):
# pylint: disable=no-member
    """Abstract base class. Must have ivars:
         - chall_doer
         - achalls
         - account_key
       And must also inherit from util.NginxTest.
    """

    def tearDown(self):
    # pylint: disable=missing-docstring
        shutil.rmtree(self.temp_dir)
        shutil.rmtree(self.config_dir)
        shutil.rmtree(self.work_dir)

    @mock.patch("certbot_nginx.configurator"
                ".NginxConfigurator.choose_vhost")
    def test_perform(self, mock_choose):
        self.chall_doer.add_chall(self.achalls[1])
        mock_choose.return_value = None
        result = self.chall_doer.perform()
        self.assertFalse(result is None)

    def test_perform0(self):
        responses = self.chall_doer.perform()
        self.assertEqual([], responses)

    @mock.patch("certbot_nginx.configurator.NginxConfigurator.save")
    def test_perform1(self, mock_save):
        self.chall_doer.add_chall(self.achalls[0])
        response = self.achalls[0].response(self.account_key)
        mock_setup_cert = mock.MagicMock(return_value=response)

        # pylint: disable=protected-access
        if hasattr(self.chall_doer, '_setup_challenge_cert'):
            self.chall_doer._setup_challenge_cert = mock_setup_cert

        responses = self.chall_doer.perform()

        if hasattr(self.chall_doer, '_setup_challenge_cert'):
            mock_setup_cert.assert_called_once_with(self.achalls[0])
        self.assertEqual([response], responses)
        self.assertEqual(mock_save.call_count, 1)

        # Make sure challenge config is included in main config
        http = self.chall_doer.configurator.parser.parsed[
            self.chall_doer.configurator.parser.config_root][-1]
        self.assertTrue(
            util.contains_at_depth(http, ['include', self.chall_doer.challenge_conf], 1))

    def test_perform2(self):
        acme_responses = []
        for achall in self.achalls:
            self.chall_doer.add_chall(achall)
            acme_responses.append(achall.response(self.account_key))

        mock_setup_cert = mock.MagicMock(side_effect=acme_responses)
        # pylint: disable=protected-access
        if hasattr(self.chall_doer, '_setup_challenge_cert'):
            self.chall_doer._setup_challenge_cert = mock_setup_cert

        sni_responses = self.chall_doer.perform()

        if hasattr(self.chall_doer, '_setup_challenge_cert'):
            self.assertEqual(mock_setup_cert.call_count, 4)

            for index, achall in enumerate(self.achalls):
                self.assertEqual(
                    mock_setup_cert.call_args_list[index], mock.call(achall))

        http = self.chall_doer.configurator.parser.parsed[
            self.chall_doer.configurator.parser.config_root][-1]
        self.assertTrue(['include', self.chall_doer.challenge_conf] in http[1])
        self.assertFalse(
            util.contains_at_depth(http, ['server_name', 'another.alias'], 3))

        self.assertEqual(len(sni_responses), 4)
        for i in six.moves.range(4):
            self.assertEqual(sni_responses[i], acme_responses[i])

    def test_mod_config(self):
        self.chall_doer.add_chall(self.achalls[0])
        self.chall_doer.add_chall(self.achalls[2])

        v_addr1 = [obj.Addr("69.50.225.155", "9000", True, False, False, False),
                   obj.Addr("127.0.0.1", "", False, False, False, False)]
        v_addr2 = [obj.Addr("myhost", "", False, True, False, False)]
        v_addr2_print = [obj.Addr("myhost", "", False, False, False, False)]
        ll_addr = [v_addr1, v_addr2]
        self.chall_doer._mod_config(ll_addr)  # pylint: disable=protected-access

        self.chall_doer.configurator.save()

        self.chall_doer.configurator.parser.load()

        http = self.chall_doer.configurator.parser.parsed[
            self.chall_doer.configurator.parser.config_root][-1]
        self.assertTrue(['include', self.chall_doer.challenge_conf] in http[1])

        vhosts = self.chall_doer.configurator.parser.get_vhosts()
        vhs = [vh for vh in vhosts if vh.filep == self.chall_doer.challenge_conf]

        for vhost in vhs:
            if vhost.addrs == set(v_addr1):
                achall = self.achalls[0]
                response = achall.response(self.account_key)
            else:
                achall = self.achalls[2]
                response = achall.response(self.account_key)
                self.assertEqual(vhost.addrs, set(v_addr2_print))
            if hasattr(response, 'z_domain'):
                domain = response.z_domain.decode('ascii')
            else:
                domain = achall.domain
            self.assertEqual(vhost.names, set([domain]))

        self.assertEqual(len(vhs), 2)

    def test_mod_config_fail(self):
        root = self.chall_doer.configurator.parser.config_root
        self.chall_doer.configurator.parser.parsed[root] = [['include', 'foo.conf']]
        # pylint: disable=protected-access
        self.assertRaises(
            errors.MisconfigurationError, self.chall_doer._mod_config, [])


class TlsSniPerformTest(util.NginxTest, ChallengePerformTest):
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
        util.NginxTest.setUp(self)

        config = util.get_nginx_configurator(
            self.config_path, self.config_dir, self.work_dir, self.logs_dir)

        from certbot_nginx import challenges as nginx_challenges
        self.chall_doer = nginx_challenges.NginxTlsSni01(config)


class HttpPerformTest(util.NginxTest, ChallengePerformTest):
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
            domain="another.alias", account_key=account_key),
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
            domain="sslon.com", account_key=account_key),
    ]

    def setUp(self):
        util.NginxTest.setUp(self)

        config = util.get_nginx_configurator(
            self.config_path, self.config_dir, self.work_dir, self.logs_dir)

        from certbot_nginx import challenges as nginx_challenges
        self.chall_doer = nginx_challenges.NginxHttp01(config)


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
