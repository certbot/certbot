"""Tests for acme.errors."""
import sys
import unittest
from unittest import mock

import pytest


class BadNonceTest(unittest.TestCase):
    """Tests for acme.errors.BadNonce."""

    def setUp(self):
        from acme.errors import BadNonce
        self.error = BadNonce(nonce="xxx", error="error")

    def test_str(self):
        self.assertEqual("Invalid nonce ('xxx'): error", str(self.error))


class MissingNonceTest(unittest.TestCase):
    """Tests for acme.errors.MissingNonce."""

    def setUp(self):
        from acme.errors import MissingNonce
        self.response = mock.MagicMock(headers={})
        self.response.request.method = 'FOO'
        self.error = MissingNonce(self.response)

    def test_str(self):
        self.assertIn("FOO", str(self.error))
        self.assertIn("{}", str(self.error))


class PollErrorTest(unittest.TestCase):
    """Tests for acme.errors.PollError."""

    def setUp(self):
        from acme.errors import PollError
        self.timeout = PollError(
            exhausted={mock.sentinel.AR},
            updated={})
        self.invalid = PollError(exhausted=set(), updated={
            mock.sentinel.AR: mock.sentinel.AR2})

    def test_timeout(self):
        self.assertTrue(self.timeout.timeout)
        self.assertFalse(self.invalid.timeout)

    def test_repr(self):
        self.assertEqual('PollError(exhausted=%s, updated={sentinel.AR: '
                         'sentinel.AR2})' % repr(set()), repr(self.invalid))


if __name__ == "__main__":
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover
