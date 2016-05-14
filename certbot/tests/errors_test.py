"""Tests for certbot.errors."""
import unittest

import mock

from acme import messages

from certbot import achallenges
from certbot.tests import acme_util


class FaiiledChallengesTest(unittest.TestCase):
    """Tests for certbot.errors.FailedChallenges."""

    def setUp(self):
        from certbot.errors import FailedChallenges
        self.error = FailedChallenges(set([achallenges.DNS(
            domain="example.com", challb=messages.ChallengeBody(
                chall=acme_util.DNS, uri=None,
                error=messages.Error(typ="tls", detail="detail")))]))

    def test_str(self):
        self.assertTrue(str(self.error).startswith(
            "Failed authorization procedure. example.com (dns): tls"))


class StandaloneBindErrorTest(unittest.TestCase):
    """Tests for certbot.errors.StandaloneBindError."""

    def setUp(self):
        from certbot.errors import StandaloneBindError
        self.error = StandaloneBindError(mock.sentinel.error, 1234)

    def test_instance_args(self):
        self.assertEqual(mock.sentinel.error, self.error.socket_error)
        self.assertEqual(1234, self.error.port)

    def test_str(self):
        self.assertTrue(str(self.error).startswith(
            "Problem binding to port 1234: "))


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
