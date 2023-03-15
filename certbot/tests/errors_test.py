"""Tests for certbot.errors."""
import sys
import unittest
from unittest import mock

import pytest

from acme import messages
from certbot import achallenges
from certbot.tests import acme_util


class FailedChallengesTest(unittest.TestCase):
    """Tests for certbot.errors.FailedChallenges."""

    def setUp(self) -> None:
        from certbot.errors import FailedChallenges
        self.error = FailedChallenges({achallenges.DNS(
            domain="example.com", challb=messages.ChallengeBody(
                chall=acme_util.DNS01, uri=None,
                error=messages.Error.with_code("tls", detail="detail")))})

    def test_str(self) -> None:
        assert str(self.error).startswith(
            "Failed authorization procedure. example.com (dns-01): "
            "urn:ietf:params:acme:error:tls")

    def test_unicode(self) -> None:
        from certbot.errors import FailedChallenges
        arabic_detail = u'\u0639\u062f\u0627\u0644\u0629'
        arabic_error = FailedChallenges({achallenges.DNS(
            domain="example.com", challb=messages.ChallengeBody(
                chall=acme_util.DNS01, uri=None,
                error=messages.Error.with_code("tls", detail=arabic_detail)))})

        assert str(arabic_error).startswith(
            "Failed authorization procedure. example.com (dns-01): "
            "urn:ietf:params:acme:error:tls")


class StandaloneBindErrorTest(unittest.TestCase):
    """Tests for certbot.errors.StandaloneBindError."""

    def setUp(self) -> None:
        from certbot.errors import StandaloneBindError
        self.error = StandaloneBindError(mock.sentinel.error, 1234)

    def test_instance_args(self) -> None:
        assert mock.sentinel.error == self.error.socket_error
        assert 1234 == self.error.port

    def test_str(self) -> None:
        assert str(self.error).startswith(
            "Problem binding to port 1234: ")


if __name__ == "__main__":
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover
