"""Tests for letsencrypt.plugins.manual."""
import unittest

import mock

from acme import challenges

from letsencrypt import achallenges
from letsencrypt.tests import acme_util


class ManualAuthenticatorTest(unittest.TestCase):
    """Tests for letsencrypt.plugins.manual.ManualAuthenticator."""

    def setUp(self):
        from letsencrypt.plugins.manual import ManualAuthenticator
        self.config = mock.MagicMock(
            no_simple_http_tls=True, simple_http_port=4430,
            manual_test_mode=False)
        self.auth = ManualAuthenticator(config=self.config, name="manual")
        self.achalls = [achallenges.SimpleHTTP(
            challb=acme_util.SIMPLE_HTTP, domain="foo.com", key=None)]

    def test_more_info(self):
        self.assertTrue(isinstance(self.auth.more_info(), str))

    def test_get_chall_pref(self):
        self.assertTrue(all(issubclass(pref, challenges.Challenge)
                            for pref in self.auth.get_chall_pref("foo.com")))

    def test_perform_empty(self):
        self.assertEqual([], self.auth.perform([]))

    @mock.patch("letsencrypt.plugins.manual.sys.stdout")
    @mock.patch("letsencrypt.plugins.manual.os.urandom")
    @mock.patch("acme.challenges.SimpleHTTPResponse.simple_verify")
    @mock.patch("__builtin__.raw_input")
    def test_perform(self, mock_raw_input, mock_verify, mock_urandom,
                     mock_stdout):
        mock_urandom.return_value = "foo"
        mock_verify.return_value = True

        resp = challenges.SimpleHTTPResponse(tls=False, path='Zm9v')
        self.assertEqual([resp], self.auth.perform(self.achalls))
        self.assertEqual(1, mock_raw_input.call_count)
        mock_verify.assert_called_with(self.achalls[0].challb, "foo.com", 4430)

        message = mock_stdout.write.mock_calls[0][1][0]
        self.assertTrue(self.achalls[0].token in message)
        self.assertTrue('Zm9v' in message)

        mock_verify.return_value = False
        self.assertEqual([None], self.auth.perform(self.achalls))


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
