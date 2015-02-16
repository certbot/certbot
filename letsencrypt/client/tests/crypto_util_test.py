"""Tests for letsencrypt.client.crypto_util."""
import datetime
import os
import pkg_resources
import unittest

import M2Crypto


RSA256_KEY = pkg_resources.resource_string(__name__, 'testdata/rsa256_key.pem')
RSA512_KEY = pkg_resources.resource_string(__name__, 'testdata/rsa512_key.pem')


class ValidCSRTest(unittest.TestCase):
    """Tests for letsencrypt.client.crypto_util.valid_csr."""

    @classmethod
    def _call(cls, csr):
        from letsencrypt.client.crypto_util import valid_csr
        return valid_csr(csr)

    def _call_testdata(self, name):
        return self._call(pkg_resources.resource_string(
            __name__, os.path.join('testdata', name)))

    def test_valid_pem_true(self):
        self.assertTrue(self._call_testdata('csr.pem'))

    def test_valid_pem_san_true(self):
        self.assertTrue(self._call_testdata('csr-san.pem'))

    def test_valid_der_false(self):
        self.assertFalse(self._call_testdata('csr.der'))

    def test_valid_der_san_false(self):
        self.assertFalse(self._call_testdata('csr-san.der'))

    def test_empty_false(self):
        self.assertFalse(self._call(''))

    def test_random_false(self):
        self.assertFalse(self._call('foo bar'))


class CSRMatchesPubkeyTest(unittest.TestCase):
    """Tests for letsencrypt.client.crypto_util.csr_matches_pubkey."""

    @classmethod
    def _call_testdata(cls, name, privkey):
        from letsencrypt.client.crypto_util import csr_matches_pubkey
        return csr_matches_pubkey(pkg_resources.resource_string(
            __name__, os.path.join('testdata', name)), privkey)

    def test_valid_true(self):
        self.assertTrue(self._call_testdata('csr.pem', RSA256_KEY))

    def test_invalid_false(self):
        self.assertFalse(self._call_testdata('csr.pem', RSA512_KEY))


class MakeKeyTest(unittest.TestCase):  # pylint: disable=too-few-public-methods
    """Tests for letsencrypt.client.crypto_util.make_key."""

    def test_it(self):  # pylint: disable=no-self-use
        from letsencrypt.client.crypto_util import make_key
        M2Crypto.RSA.load_key_string(make_key(1024))
        M2Crypto.RSA.load_key_string(make_key(2048))
        M2Crypto.RSA.load_key_string(make_key(4096))


class MakeCSRTest(unittest.TestCase):
    # pylint: disable=too-few-public-methods,bad-continuation
    """Tests for letsencrypt.client.crypto_util.make_csr."""
    def test_make_csr(self):
        from letsencrypt.client.crypto_util import make_csr
        result = make_csr(RSA512_KEY, ["example.com", "foo.example.com"])
        self.assertEqual(
            result, (
"""-----BEGIN CERTIFICATE REQUEST-----
MIIBbjCCARgCAQAweTELMAkGA1UEBhMCVVMxETAPBgNVBAgTCE1pY2hpZ2FuMRIw
EAYDVQQHEwlBbm4gQXJib3IxDDAKBgNVBAoTA0VGRjEfMB0GA1UECxMWVW5pdmVy
c2l0eSBvZiBNaWNoaWdhbjEUMBIGA1UEAxMLZXhhbXBsZS5jb20wXDANBgkqhkiG
9w0BAQEFAANLADBIAkEA9LYRcVE3Nr+qleecEcX8JwVDnjeG1X7ucsCasuuZM0e0
9cmYuUzxIkMjO/9x4AVcvXXRXPEV+LzWWkfkTlzRMwIDAQABoDowOAYJKoZIhvcN
AQkOMSswKTAnBgNVHREEIDAeggtleGFtcGxlLmNvbYIPZm9vLmV4YW1wbGUuY29t
MA0GCSqGSIb3DQEBCwUAA0EAAkBBkne4LNwBaZ95i1qez4Ii4nuj4Y0MaYrOe6lh
YdCQq5RRHEKCFwxcJSZQaWWwmfbR0C2E2H7SnEPrcn4Y8w==
-----END CERTIFICATE REQUEST-----
""",
            "3082016e308201180201003079310b30090603550406130255533111300f"
            "060355040813084d6963686967616e3112301006035504071309416e6e20"
            "4172626f72310c300a060355040a1303454646311f301d060355040b1316"
            "556e6976657273697479206f66204d6963686967616e3114301206035504"
            "03130b6578616d706c652e636f6d305c300d06092a864886f70d01010105"
            "00034b003048024100f4b61171513736bfaa95e79c11c5fc2705439e3786"
            "d57eee72c09ab2eb993347b4f5c998b94cf12243233bff71e0055cbd75d1"
            "5cf115f8bcd65a47e44e5cd1330203010001a03a303806092a864886f70d"
            "01090e312b302930270603551d110420301e820b6578616d706c652e636f"
            "6d820f666f6f2e6578616d706c652e636f6d300d06092a864886f70d0101"
            "0b05000341000240419277b82cdc01699f798b5a9ecf8222e27ba3e18d0c"
            "698ace7ba96161d090ab94511c4282170c5c2526506965b099f6d1d02d84"
            "d87ed29c43eb727e18f3".decode("hex")))


class ValidPrivkeyTest(unittest.TestCase):
    """Tests for letsencrypt.client.crypto_util.valid_privkey."""

    @classmethod
    def _call(cls, privkey):
        from letsencrypt.client.crypto_util import valid_privkey
        return valid_privkey(privkey)

    def test_valid_true(self):
        self.assertTrue(self._call(RSA256_KEY))

    def test_empty_false(self):
        self.assertFalse(self._call(''))

    def test_random_false(self):
        self.assertFalse(self._call('foo bar'))


class MakeSSCertTest(unittest.TestCase):
    # pylint: disable=too-few-public-methods
    """Tests for letsencrypt.client.crypto_util.make_ss_cert."""

    def test_it(self):  # pylint: disable=no-self-use
        from letsencrypt.client.crypto_util import make_ss_cert
        make_ss_cert(RSA256_KEY, ['example.com', 'www.example.com'])


class GetCertInfoTest(unittest.TestCase):
    """Tests for letsencrypt.client.crypto_util.get_cert_info."""

    def setUp(self):
        self.cert_info = {
            'not_before': datetime.datetime(
                2014, 12, 11, 22, 34, 45, tzinfo=M2Crypto.ASN1.UTC),
            'not_after': datetime.datetime(
                2014, 12, 18, 22, 34, 45, tzinfo=M2Crypto.ASN1.UTC),
            'subject': 'C=US, ST=Michigan, L=Ann Arbor, O=University '
                       'of Michigan and the EFF, CN=example.com',
            'cn': 'example.com',
            'issuer': 'C=US, ST=Michigan, L=Ann Arbor, O=University '
                      'of Michigan and the EFF, CN=example.com',
            'serial': 1337L,
            'pub_key': 'RSA 512',
        }

    def _call(self, name):
        from letsencrypt.client.crypto_util import get_cert_info
        self.assertEqual(get_cert_info(pkg_resources.resource_filename(
            __name__, os.path.join('testdata', name))), self.cert_info)

    def test_single_domain(self):
        self.cert_info.update({
            'san': '',
            'fingerprint': '9F8CE01450D288467C3326AC0457E351939C72E',
        })
        self._call('cert.pem')

    def test_san(self):
        self.cert_info.update({
            'san': 'DNS:example.com, DNS:www.example.com',
            'fingerprint': '62F7110431B8E8F55905DBE5592518F9634AC50A',
        })
        self._call('cert-san.pem')


if __name__ == '__main__':
    unittest.main()
