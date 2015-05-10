"""Tests for recovery_token.py."""
import os
import unittest
import shutil
import tempfile

import mock

from letsencrypt.acme import challenges

from letsencrypt.client import achallenges


class RecoveryTokenTest(unittest.TestCase):
    def setUp(self):
        from letsencrypt.client.recovery_token import RecoveryToken
        server = "demo_server"
        self.base_dir = tempfile.mkdtemp("tokens")
        self.token_dir = os.path.join(self.base_dir, server)
        self.rec_token = RecoveryToken(server, self.base_dir)

    def tearDown(self):
        shutil.rmtree(self.base_dir)

    def test_store_token(self):
        self.rec_token.store_token("example.com", 111)
        path = os.path.join(self.token_dir, "example.com")
        self.assertTrue(os.path.isfile(path))
        with open(path) as token_fd:
            self.assertEqual(token_fd.read(), "111")

    def test_requires_human(self):
        self.rec_token.store_token("example2.com", 222)
        self.assertFalse(self.rec_token.requires_human("example2.com"))
        self.assertTrue(self.rec_token.requires_human("example3.com"))

    def test_cleanup(self):
        self.rec_token.store_token("example3.com", 333)
        self.assertFalse(self.rec_token.requires_human("example3.com"))

        self.rec_token.cleanup(achallenges.RecoveryToken(
            challb=challenges.RecoveryToken(), domain="example3.com"))
        self.assertTrue(self.rec_token.requires_human("example3.com"))

        # Shouldn't throw an error
        self.rec_token.cleanup(achallenges.RecoveryToken(
            challb=None, domain="example4.com"))

        # SHOULD throw an error (OSError other than nonexistent file)
        self.assertRaises(
            OSError, self.rec_token.cleanup,
            achallenges.RecoveryToken(
                challb=None, domain=("a" + "r" * 10000 + ".com")))

    def test_perform_stored(self):
        self.rec_token.store_token("example4.com", 444)
        response = self.rec_token.perform(
            achallenges.RecoveryToken(
                challb=challenges.RecoveryToken(), domain="example4.com"))

        self.assertEqual(
            response, challenges.RecoveryTokenResponse(token="444"))

    @mock.patch("letsencrypt.client.recovery_token.zope.component.getUtility")
    def test_perform_not_stored(self, mock_input):
        mock_input().input.side_effect = [(0, "555"), (1, "000")]
        response = self.rec_token.perform(
            achallenges.RecoveryToken(
                challb=challenges.RecoveryToken(), domain="example5.com"))
        self.assertEqual(
            response, challenges.RecoveryTokenResponse(token="555"))

        response = self.rec_token.perform(
            achallenges.RecoveryToken(
                challb=challenges.RecoveryToken(), domain="example6.com"))
        self.assertTrue(response is None)


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
