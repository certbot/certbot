"""Tests for letsencrypt.errors."""
import unittest

from acme import messages

from letsencrypt import achallenges
from letsencrypt.tests import acme_util


class FaiiledChallengesTest(unittest.TestCase):
    """Tests for letsencrypt.errors.FailedChallenges."""

    def setUp(self):
        from letsencrypt.errors import FailedChallenges
        self.error = FailedChallenges(set([achallenges.DNS(
            domain="example.com", challb=messages.ChallengeBody(
                chall=acme_util.DNS, uri=None,
                error=messages.Error(typ="tls", detail="detail")))]))

    def test_str(self):
        self.assertTrue(str(self.error).startswith(
            "Failed authorization procedure. example.com (dns): tls"))


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
