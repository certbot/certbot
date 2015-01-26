"""Test for letsencrypt.client.ddns."""
import pkg_resources
import unittest
import shutil

import mock

from letsencrypt.client import challenge_util
from letsencrypt.client import client
from letsencrypt.client import CONFIG

from letsencrypt.client.tests.apache import util


class DDNSPerformTest(unittest.TestCase):
    """Test the DNS challenge (for dynamic DNS zones)."""

    def setUp(self):
        super(DDNSPerformTest, self).setUp()

        from letsencrypt.client.ddns import ddns
        self.ddns = ddns.DDNS()

        # XXX unclear: what is key?
        key = None
        self.challs = []
        self.challs.append(challenge_util.DnsChall(
            "encryption-example.demo", "17817c66b60ce2e4012dfad92657527a", key))
        self.challs.append(challenge_util.DnsChall(
            "letsencrypt.demo", "27817c66b60ce2e4012dfad92657527a", key))

    def tearDown(self):
        pass

    def test_pref(self):
        result = self.ddns.get_chall_pref("example.org")
        self.assertEqual(result, ["dns"])

    def test_perform0(self):
        resp = self.ddns.perform([])
        self.assertTrue(resp == [])

    @mock.patch("letsencrypt.client.ddns.ddns.nsupdate")
    def test_perform2(self, mock_nsupdate):
        responses = self.ddns.perform(self.challs)

        self.assertEqual(mock_nsupdate.call_count, 2)
        calls = mock_nsupdate.call_args_list
        expected_call_list = [
            ("update add _acme-challenge.encryption-example.demo. TXT 17817c66b60ce2e4012dfad92657527a", ),
            ("update add _acme-challenge.letsencrypt.demo. TXT 27817c66b60ce2e4012dfad92657527a", ),
        ]

        for i in range(len(expected_call_list)):
            for j in range(len(expected_call_list[0])):
                self.assertEqual(calls[i][0][j], expected_call_list[i][j])

        self.assertEqual(len(responses), 2)
        self.assertEqual(responses[0]["type"], "dns")
        self.assertEqual(responses[1]["type"], "dns")

    @mock.patch("letsencrypt.client.ddns.ddns.nsupdate")
    def test_cleanup2(self, mock_nsupdate):
        self.ddns.cleanup(self.challs)

        self.assertEqual(mock_nsupdate.call_count, 2)
        calls = mock_nsupdate.call_args_list
        expected_call_list = [
            ("update del _acme-challenge.encryption-example.demo. TXT 17817c66b60ce2e4012dfad92657527a", ),
            ("update del _acme-challenge.letsencrypt.demo. TXT 27817c66b60ce2e4012dfad92657527a", ),
        ]

        for i in range(len(expected_call_list)):
            for j in range(len(expected_call_list[0])):
                self.assertEqual(calls[i][0][j], expected_call_list[i][j])


if __name__ == '__main__':
    unittest.main()
