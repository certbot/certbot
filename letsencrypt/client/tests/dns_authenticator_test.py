"""Tests for letsencrypt.client.dns_authenticator."""
import unittest

import mock

import dns.exception
import dns.message
import dns.query
import dns.resolver
import dns.rcode

from letsencrypt.acme import challenges

from letsencrypt.client import achallenges
from letsencrypt.client import errors


class PerformCleanupTest(unittest.TestCase): # pylint: disable=too-many-public-methods
    """Test DNS perform function."""

    def setUp(self):
        from letsencrypt.client.dns_authenticator import DNSAuthenticator

        self.authenticator = DNSAuthenticator(mock.MagicMock(
            dns_server="localhost",
            dns_server_port=53,
            dns_tsig_keys=[
                [
                    "example.key",
                    "+Cdjlkef9ZTSeixERZ433Q==",
                    ["example.com", "final-example.com"]
                ],
                [
                    "other-example.key",
                    "+Lkalkef7EdSeixZXC433Q==",
                    ["other-example.com"]
                ]
            ]
        ))

        good_chall = achallenges.DNS(
            chall=challenges.DNS(token="17817c66b60ce2e4012dfad92657527"),
            domain="example.com")
        second_good_chall = achallenges.DNS(
            chall=challenges.DNS(token="17817c66b60ce2e4012dfad92657527"),
            domain="other-example.com")
        third_good_chall = achallenges.DNS(
            chall=challenges.DNS(token="17817c66b60ce2e4012dfad92657527"),
            domain="final-example.com")

        no_key_chall = achallenges.DNS(
            chall=challenges.DNS(token="17817c66b60ce2e4012dfad92657527"),
            domain="no-key-example.com")

        self.achalls = [
            good_chall,
            second_good_chall,
            third_good_chall,
            no_key_chall,
        ]

        self.good_dns_msg = dns.message.Message()
        self.good_dns_msg.set_rcode(dns.rcode.NOERROR)

        self.bad_dns_msgs = []
        bad_rcodes = [
            dns.rcode.FORMERR,
            dns.rcode.SERVFAIL,
            dns.rcode.NXDOMAIN,
            dns.rcode.NOTIMP,
            dns.rcode.REFUSED,
            dns.rcode.YXDOMAIN,
            dns.rcode.YXRRSET,
            dns.rcode.NXRRSET,
            dns.rcode.NOTAUTH,
            dns.rcode.NOTZONE,
            dns.rcode.BADVERS,
        ]
        for rcode in bad_rcodes:
            bad_dns_msg = dns.message.Message()
            bad_dns_msg.set_rcode(rcode)
            self.bad_dns_msgs.append(bad_dns_msg)

        self.dns_exceptions = [
            dns.resolver.NoAnswer,
            dns.query.UnexpectedSource,
            dns.query.BadResponse,
            OSError,
            dns.exception.Timeout,
        ]

    def test_chall_pref(self):
        self.assertEqual(
            self.authenticator.get_chall_pref("example.com"), [challenges.DNS])

    def test_good_challs_perform(self):
        with mock.patch("dns.query.tcp") as query:
            query.return_value = self.good_dns_msg

            results = self.authenticator.perform(self.achalls[:3])

            self.assertTrue(isinstance(results, list))
            self.assertEqual(len(results), 3)
            self.assertTrue(
                isinstance(results[0], challenges.ChallengeResponse))
            self.assertTrue(
                isinstance(results[1], challenges.ChallengeResponse))
            self.assertTrue(
                isinstance(results[2], challenges.ChallengeResponse))

    def test_bad_challs_perform(self):
        # bad DNS message responses
        for bad_dns_msg in self.bad_dns_msgs:
            with mock.patch("dns.query.tcp") as query:
                query.return_value = bad_dns_msg

                self.assertRaises(errors.LetsEncryptDNSAuthError,
                                  self.authenticator.perform,
                                  [self.achalls[0]])

        # query exceptions
        for excep in self.dns_exceptions:
            with mock.patch("dns.query.tcp") as query:
                query.side_effect = excep

                self.assertRaises(errors.LetsEncryptDNSAuthError,
                                  self.authenticator.perform,
                                  [self.achalls[0]])

        # no TSIG key
        self.assertRaises(errors.LetsEncryptDNSAuthError,
                          self.authenticator.perform, [self.achalls[3]])

    def test_good_cleanup(self):
        with mock.patch("dns.query.tcp") as query:
            query.return_value = self.good_dns_msg

            self.authenticator.cleanup(self.achalls[:3])

    def test_bad_challs_cleanup(self):
        # bad DNS message responses
        for bad_dns_msg in self.bad_dns_msgs:
            with mock.patch("dns.query.tcp") as query:
                query.return_value = bad_dns_msg

                self.assertRaises(errors.LetsEncryptDNSAuthError,
                                  self.authenticator.cleanup,
                                  [self.achalls[0]])

        # query exceptions
        for excep in self.dns_exceptions:
            with mock.patch("dns.query.tcp") as query:
                query.side_effect = excep

                self.assertRaises(errors.LetsEncryptDNSAuthError,
                                  self.authenticator.perform,
                                  [self.achalls[0]])

        # no TSIG key
        self.assertRaises(errors.LetsEncryptDNSAuthError,
                          self.authenticator.cleanup, [self.achalls[3]])

    def test_no_tsig_keys(self):
        # no TSIG keys at all
        from letsencrypt.client.dns_authenticator import DNSAuthenticator
        magic = mock.MagicMock(dns_server="localhost", dns_server_port=53,
                               dns_tsig_keys=None)
        self.assertRaises(errors.LetsEncryptDNSAuthError, DNSAuthenticator,
                          magic)


if __name__ == '__main__':
    unittest.main()
