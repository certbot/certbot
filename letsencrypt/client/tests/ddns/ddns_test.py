"""Test for letsencrypt.client.ddns."""
import unittest
import subprocess

import mock

from letsencrypt.client import CONFIG
from letsencrypt.client import challenge_util
from letsencrypt.client.ddns import ddns


class DDNSPerformTest(unittest.TestCase):
    """Test the DNS challenge (for dynamic DNS zones)."""

    def setUp(self):
        super(DDNSPerformTest, self).setUp()
        self.ddns = ddns.DDNS()

        # XXX unclear: what is key?
        key = None
        self.challs = []
        self.challs.append(challenge_util.DnsChall(
            "encryption-example.demo", "17817c66b60ce2e4012dfad92657527a", key))
        self.challs.append(challenge_util.DnsChall(
            "letsencrypt.demo", "27817c66b60ce2e4012dfad92657527a", key))

    def test_pref(self):
        result = self.ddns.get_chall_pref("example.org")
        self.assertEqual(result, ["dns"])

    def test_perform0(self):
        resp = self.ddns.perform([])
        self.assertEqual(resp, [])

    @mock.patch("letsencrypt.client.ddns.ddns.nsupdate")
    def test_perform2(self, mock_nsupdate):
        responses = self.ddns.perform(self.challs)

        self.assertEqual(mock_nsupdate.call_count, 2)
        calls = mock_nsupdate.call_args_list
        expected_call_list = [
            ("add", "encryption-example.demo",
             "17817c66b60ce2e4012dfad92657527a", ),
            ("add", "letsencrypt.demo",
             "27817c66b60ce2e4012dfad92657527a", ),
        ]

        for i in xrange(len(expected_call_list)):
            for j in xrange(len(expected_call_list[0])):
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
            ("del", "encryption-example.demo",
             "17817c66b60ce2e4012dfad92657527a", ),
            ("del", "letsencrypt.demo",
             "27817c66b60ce2e4012dfad92657527a", ),
        ]

        for i in xrange(len(expected_call_list)):
            for j in xrange(len(expected_call_list[0])):
                self.assertEqual(calls[i][0][j], expected_call_list[i][j])


class NsupdateTest(unittest.TestCase):
    """Test the nsupdate function."""

    @mock.patch("letsencrypt.client.ddns.ddns.subprocess.Popen")
    def test_nsupdate_success(self, mock_popen):
        # communicate return values are just logged, but not evaluated
        mock_popen().communicate.return_value = ("", "")
        # return code 0 indicates nsupdate success
        mock_popen().poll.return_value = 0
        ddns.nsupdate("add", "example.org", "42")
        self.assertEqual(mock_popen.call_count, 3)
        self.assertEqual(mock_popen.call_args_list[2],
                         mock.call(CONFIG.NSUPDATE_CMD.split(),
                                   stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE))
        self.assertEqual(mock_popen().communicate.call_count, 1)
        call_args = mock_popen().communicate.call_args_list[0]
        call_args_expected = mock.call(
            input='update add _acme-challenge.example.org. 60 TXT 42\nsend\n')
        self.assertEqual(call_args, call_args_expected)

    @mock.patch("letsencrypt.client.ddns.ddns.subprocess.Popen")
    def test_nsupdate_failure(self, mock_popen):
        # communicate return values are just logged, but not evaluated
        mock_popen().communicate.return_value = ("", "")
        # return code 2 indicates nsupdate failure (REJECTED)
        mock_popen().poll.return_value = 2
        self.assertRaises(subprocess.CalledProcessError,
                          ddns.nsupdate, "del", "example.org", "42")
        self.assertEqual(mock_popen.call_count, 3)
        self.assertEqual(mock_popen.call_args_list[2],
                         mock.call(CONFIG.NSUPDATE_CMD.split(),
                                   stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE))
        self.assertEqual(mock_popen().communicate.call_count, 1)
        call_args = mock_popen().communicate.call_args_list[0]
        call_args_expected = mock.call(
            input='update del _acme-challenge.example.org. 60 TXT 42\nsend\n')
        self.assertEqual(call_args, call_args_expected)


if __name__ == '__main__':
    unittest.main()
