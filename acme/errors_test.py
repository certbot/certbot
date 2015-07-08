"""Tests for acme.errors."""
import unittest

import mock


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
        self.assertTrue("FOO" in str(self.error))
        self.assertTrue("{}" in str(self.error))


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
