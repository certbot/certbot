"""Test for letsencrypt.continuity_auth."""
import unittest

import mock

from acme import challenges

from letsencrypt import achallenges
from letsencrypt import errors


class PerformTest(unittest.TestCase):
    """Test client perform function."""

    def setUp(self):
        from letsencrypt.continuity_auth import ContinuityAuthenticator

        self.auth = ContinuityAuthenticator(
            mock.MagicMock(server="demo_server.org"), None)
        self.auth.proof_of_pos.perform = mock.MagicMock(
            name="proof_of_pos_perform", side_effect=gen_client_resp)

    def test_pop(self):
        achalls = []
        for i in xrange(4):
            achalls.append(achallenges.ProofOfPossession(
                challb=None, domain=str(i)))
        responses = self.auth.perform(achalls)

        self.assertEqual(len(responses), 4)
        for i in xrange(4):
            self.assertEqual(responses[i], "ProofOfPossession%d" % i)

    def test_unexpected(self):
        self.assertRaises(
            errors.ContAuthError, self.auth.perform, [
                achallenges.KeyAuthorizationAnnotatedChallenge(
                    challb=None, domain="0", account_key="invalid_key")])

    def test_chall_pref(self):
        self.assertEqual(
            self.auth.get_chall_pref("example.com"),
            [challenges.ProofOfPossession])


class CleanupTest(unittest.TestCase):
    """Test the Authenticator cleanup function."""

    def setUp(self):
        from letsencrypt.continuity_auth import ContinuityAuthenticator

        self.auth = ContinuityAuthenticator(
            mock.MagicMock(server="demo_server.org"), None)

    def test_unexpected(self):
        unexpected = achallenges.KeyAuthorizationAnnotatedChallenge(
            challb=None, domain="0", account_key="dummy_key")
        self.assertRaises(errors.ContAuthError, self.auth.cleanup, [unexpected])


def gen_client_resp(chall):
    """Generate a dummy response."""
    return "%s%s" % (chall.__class__.__name__, chall.domain)


if __name__ == '__main__':
    unittest.main()  # pragma: no cover
