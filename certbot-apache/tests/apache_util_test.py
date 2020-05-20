"""Tests for certbot_apache._internal.apache_util."""
import unittest

import certbot.tests.util as test_util


class CertFingerprintTest(unittest.TestCase):
    """Tests for certbot_apache._internal.apache_util.cert_sha1_fingerprint"""

    def test_cert_sha1_fingerprint(self):
        from certbot_apache._internal.apache_util import cert_sha1_fingerprint

        cert_path = test_util.vector_path('cert_512.pem')
        self.assertEqual(
            cert_sha1_fingerprint(cert_path),
            b'\t\xf8\xce\x01E\r(\x84g\xc32j\xc0E~5\x199\xc7.'
        )


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
