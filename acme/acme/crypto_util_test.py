"""Tests for acme.crypto_util."""
import socket
import unittest

import OpenSSL


class ProbeSNITest(unittest.TestCase):
    """Tests for acme.crypto_util._probe_sni."""

    def test_it(self):
        from acme.crypto_util import _probe_sni
        # TODO: mock this out
        cert = _probe_sni(
            "google.com", socket.gethostbyname("google.com"), port=443)
        self.assertTrue(isinstance(cert, OpenSSL.crypto.X509))


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
