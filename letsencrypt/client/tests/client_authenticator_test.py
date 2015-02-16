"""Test the ClientAuthenticator dispatcher."""
import unittest

import mock

from letsencrypt.client import challenge_util
from letsencrypt.client import errors


class PerformTest(unittest.TestCase):
    """Test client perform function."""

    def setUp(self):
        from letsencrypt.client.client_authenticator import ClientAuthenticator

        self.auth = ClientAuthenticator(
            mock.MagicMock(server="demo_server.org"))
        self.auth.rec_token.perform = mock.MagicMock(
            name="rec_token_perform", side_effect=gen_client_resp)

    def test_rec_token1(self):
        token = challenge_util.RecTokenChall("0")
        responses = self.auth.perform([token])
        self.assertEqual(responses, ["RecTokenChall0"])

    def test_rec_token5(self):
        tokens = []
        for i in xrange(5):
            tokens.append(challenge_util.RecTokenChall(str(i)))

        responses = self.auth.perform(tokens)

        self.assertEqual(len(responses), 5)
        for i in xrange(5):
            self.assertEqual(responses[i], "RecTokenChall%d" % i)

    def test_unexpected(self):
        unexpected = challenge_util.DvsniChall(
            "0", "rb64", "123", "invalid_key")

        self.assertRaises(
            errors.LetsEncryptClientAuthError, self.auth.perform, [unexpected])

    def test_chall_pref(self):
        self.assertEqual(
            self.auth.get_chall_pref("example.com"), ["recoveryToken"])


class CleanupTest(unittest.TestCase):
    """Test the Authenticator cleanup function."""

    def setUp(self):
        from letsencrypt.client.client_authenticator import ClientAuthenticator

        self.auth = ClientAuthenticator(
            mock.MagicMock(server="demo_server.org"))
        self.mock_cleanup = mock.MagicMock(name="rec_token_cleanup")
        self.auth.rec_token.cleanup = self.mock_cleanup

    def test_rec_token2(self):
        token1 = challenge_util.RecTokenChall("0")
        token2 = challenge_util.RecTokenChall("1")

        self.auth.cleanup([token1, token2])

        self.assertEqual(self.mock_cleanup.call_args_list,
                         [mock.call(token1), mock.call(token2)])

    def test_unexpected(self):
        token = challenge_util.RecTokenChall("0")
        unexpected = challenge_util.DvsniChall("0", "rb64", "123", "dummy_key")

        self.assertRaises(errors.LetsEncryptClientAuthError,
                          self.auth.cleanup, [token, unexpected])


def gen_client_resp(chall):
    """Generate a dummy response."""
    return "%s%s" % (chall.__class__.__name__, chall.domain)


if __name__ == '__main__':
    unittest.main()
