"""Tests for letsencrypt.plugins.manual.authenticator."""
import unittest

import mock
import requests

from acme import challenges

from letsencrypt import achallenges
from letsencrypt.tests import acme_util


class ManualAuthenticatorTest(unittest.TestCase):
    """Tests for letsencrypt.plugins.manual.authenticator.ManualAuthenticator."""

    def setUp(self):
        from letsencrypt.plugins.manual.authenticator import ManualAuthenticator
        self.config = mock.MagicMock(no_simple_http_tls=True)
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

    @mock.patch("letsencrypt.plugins.manual.authenticator.sys.stdout")
    @mock.patch("letsencrypt.plugins.manual.authenticator.os.urandom")
    @mock.patch("letsencrypt.plugins.manual.authenticator.requests.get")
    @mock.patch("__builtin__.raw_input")
    def test_perform(self, mock_raw_input, mock_get, mock_urandom, mock_stdout):
        mock_urandom.return_value = "foo"
        mock_get().text = self.achalls[0].token

        self.assertEqual(
            [challenges.SimpleHTTPResponse(tls=False, path='Zm9v')],
            self.auth.perform(self.achalls))
        mock_raw_input.assert_called_once()
        mock_get.assert_called_with(
            "http://foo.com/.well-known/acme-challenge/Zm9v", verify=False)

        message = mock_stdout.write.mock_calls[0][1][0]
        self.assertTrue(self.achalls[0].token in message)
        self.assertTrue('Zm9v' in message)

        mock_get().text = self.achalls[0].token + '!'
        self.assertEqual([None], self.auth.perform(self.achalls))

        mock_get.side_effect = requests.exceptions.ConnectionError
        self.assertEqual([None], self.auth.perform(self.achalls))


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
