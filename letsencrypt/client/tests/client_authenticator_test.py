"""Test the ClientAuthenticator dispatcher."""
import unittest

import mock


class PerformTest(unittest.TestCase):
    """Test client perform function."""

    def setUp(self):
        from letsencrypt.client.client_authenticator import ClientAuthenticator

        self.auth = ClientAuthenticator(
            mock.MagicMock(acme_server="demo_server.org"))
        self.auth.rec_token.perform = mock.MagicMock(
            name="rec_token_perform", side_effect=gen_client_resp)

    def test_rec_token1(self):
        from letsencrypt.client.challenge_util import RecTokenChall
        token = RecTokenChall("0")

        responses = self.auth.perform([token])

        self.assertEqual(responses, ["RecTokenChall0"])

    def test_rec_token5(self):
        from letsencrypt.client.challenge_util import RecTokenChall
        tokens = []
        for i in range(5):
            tokens.append(RecTokenChall(str(i)))

        responses = self.auth.perform(tokens)

        self.assertEqual(len(responses), 5)
        for i in range(5):
            self.assertEqual(responses[i], "RecTokenChall%d" % i)

    def test_unexpected(self):
        from letsencrypt.client.challenge_util import DvsniChall
        from letsencrypt.client.errors import LetsEncryptClientAuthError

        unexpected = DvsniChall("0", "rb64", "123", "invalid_key")

        self.assertRaises(
            LetsEncryptClientAuthError, self.auth.perform, [unexpected])


class CleanupTest(unittest.TestCase):
    """Test the Authenticator cleanup function."""

    def setUp(self):
        from letsencrypt.client.client_authenticator import ClientAuthenticator

        self.auth = ClientAuthenticator(mock.MagicMock(
            acme_server="demo_server.org"))
        self.mock_cleanup = mock.MagicMock(name="rec_token_cleanup")
        self.auth.rec_token.cleanup = self.mock_cleanup

    def test_rec_token2(self):
        from letsencrypt.client.challenge_util import RecTokenChall
        token1 = RecTokenChall("0")
        token2 = RecTokenChall("1")

        self.auth.cleanup([token1, token2])

        self.assertEqual(self.mock_cleanup.call_args_list,
                         [mock.call(token1), mock.call(token2)])

    def test_unexpected(self):
        from letsencrypt.client.challenge_util import DvsniChall
        from letsencrypt.client.challenge_util import RecTokenChall
        from letsencrypt.client.errors import LetsEncryptClientAuthError

        token = RecTokenChall("0")
        unexpected = DvsniChall("0", "rb64", "123", "dummy_key")

        self.assertRaises(
            LetsEncryptClientAuthError, self.auth.cleanup, [token, unexpected])


def gen_client_resp(chall):
    """Generate a dummy response."""
    return "%s%s" % (type(chall).__name__, chall.domain)


if __name__ == '__main__':
    unittest.main()
