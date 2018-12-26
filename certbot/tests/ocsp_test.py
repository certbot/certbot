"""Tests for ocsp.py"""
# pylint: disable=protected-access
import os
import unittest
import tempfile
import shutil
import datetime

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography import x509
try:
    from cryptography.x509 import ocsp as ocsp_lib  # pylint: disable=import-error
except ImportError:
    ocsp_lib = None  # type: ignore
import mock

from certbot import errors

out = """Missing = in header key=value
ocsp: Use -help for summary.
"""


class OCSPTestOpenSSL(unittest.TestCase):
    """
    OCSP revokation tests using OpenSSL binary.
    """

    def setUp(self):
        from certbot import ocsp
        with mock.patch('certbot.ocsp.Popen') as mock_popen:
            with mock.patch('certbot.util.exe_exists') as mock_exists:
                mock_communicate = mock.MagicMock()
                mock_communicate.communicate.return_value = (None, out)
                mock_popen.return_value = mock_communicate
                mock_exists.return_value = True
                self.checker = ocsp.RevocationChecker(enforce_openssl_binary_usage=True)

    def tearDown(self):
        pass

    @mock.patch('certbot.ocsp.logger.info')
    @mock.patch('certbot.ocsp.Popen')
    @mock.patch('certbot.util.exe_exists')
    def test_init(self, mock_exists, mock_popen, mock_log):
        mock_communicate = mock.MagicMock()
        mock_communicate.communicate.return_value = (None, out)
        mock_popen.return_value = mock_communicate
        mock_exists.return_value = True

        from certbot import ocsp
        checker = ocsp.RevocationChecker(enforce_openssl_binary_usage=True)
        self.assertEqual(mock_popen.call_count, 1)
        self.assertEqual(checker.host_args("x"), ["Host=x"])

        mock_communicate.communicate.return_value = (None, out.partition("\n")[2])
        checker = ocsp.RevocationChecker(enforce_openssl_binary_usage=True)
        self.assertEqual(checker.host_args("x"), ["Host", "x"])
        self.assertEqual(checker.broken, False)

        mock_exists.return_value = False
        mock_popen.call_count = 0
        checker = ocsp.RevocationChecker(enforce_openssl_binary_usage=True)
        self.assertEqual(mock_popen.call_count, 0)
        self.assertEqual(mock_log.call_count, 1)
        self.assertEqual(checker.broken, True)

    @mock.patch('certbot.ocsp.RevocationChecker._determine_ocsp_server')
    @mock.patch('certbot.util.run_script')
    def test_ocsp_revoked(self, mock_run, mock_determine):
        self.checker.broken = True
        mock_determine.return_value = ("", "")
        self.assertEqual(self.checker.ocsp_revoked("x", "y"), False)

        self.checker.broken = False
        mock_run.return_value = tuple(openssl_happy[1:])
        self.assertEqual(self.checker.ocsp_revoked("x", "y"), False)
        self.assertEqual(mock_run.call_count, 0)

        mock_determine.return_value = ("http://x.co", "x.co")
        self.assertEqual(self.checker.ocsp_revoked("blah.pem", "chain.pem"), False)
        mock_run.side_effect = errors.SubprocessError("Unable to load certificate launcher")
        self.assertEqual(self.checker.ocsp_revoked("x", "y"), False)
        self.assertEqual(mock_run.call_count, 2)

    def test_determine_ocsp_server(self):
        tmpdir = tempfile.mkdtemp()
        try:
            cert_path = os.path.join(tmpdir, 'cert.pem')
            with open(cert_path, 'w') as file_handler:
                file_handler.write(google_certificate)

            from certbot import ocsp
            result = ocsp.RevocationChecker._determine_ocsp_server(cert_path)
            self.assertEqual(('http://ocsp.digicert.com', 'ocsp.digicert.com'), result)
        finally:
            shutil.rmtree(tmpdir)

    @mock.patch('certbot.ocsp.logger')
    @mock.patch('certbot.util.run_script')
    def test_translate_ocsp(self, mock_run, mock_log):
        # pylint: disable=protected-access,star-args
        mock_run.return_value = openssl_confused
        from certbot import ocsp
        self.assertEqual(ocsp._translate_ocsp_query(*openssl_happy), False)
        self.assertEqual(ocsp._translate_ocsp_query(*openssl_confused), False)
        self.assertEqual(mock_log.debug.call_count, 1)
        self.assertEqual(mock_log.warning.call_count, 0)
        mock_log.debug.call_count = 0
        self.assertEqual(ocsp._translate_ocsp_query(*openssl_unknown), False)
        self.assertEqual(mock_log.debug.call_count, 1)
        self.assertEqual(mock_log.warning.call_count, 0)
        self.assertEqual(ocsp._translate_ocsp_query(*openssl_expired_ocsp), False)
        self.assertEqual(mock_log.debug.call_count, 2)
        self.assertEqual(ocsp._translate_ocsp_query(*openssl_broken), False)
        self.assertEqual(mock_log.warning.call_count, 1)
        mock_log.info.call_count = 0
        self.assertEqual(ocsp._translate_ocsp_query(*openssl_revoked), True)
        self.assertEqual(mock_log.info.call_count, 0)
        self.assertEqual(ocsp._translate_ocsp_query(*openssl_expired_ocsp_revoked), True)
        self.assertEqual(mock_log.info.call_count, 1)


@unittest.skipIf(not ocsp_lib,
                 reason='This class tests functionalities available only on cryptography >= 2.4.0')
class OSCPTestCryptography(unittest.TestCase):
    """
    OCSP revokation tests using Cryptography >= 2.4.0
    """

    def setUp(self):
        from certbot import ocsp
        self.checker = ocsp.RevocationChecker()
        self.tmpdir = tempfile.mkdtemp()
        self.cert_path = os.path.join(self.tmpdir, 'cert.pem')
        self.chain_path = os.path.join(self.tmpdir, 'chain.pem')
        with open(self.cert_path, 'w') as file_handler:
            file_handler.write(google_certificate)
        with open(self.chain_path, 'w') as file_handler:
            file_handler.write(google_issuer_certificate)

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    @mock.patch('certbot.ocsp.RevocationChecker._determine_ocsp_server')
    @mock.patch('certbot.ocsp.RevocationChecker._ocsp_revoke_cryptography')
    def test_ensure_cryptography_toggled(self, mock_revoke, mock_determine):
        mock_determine.return_value = ('http://example.com', 'example.com')
        self.checker.ocsp_revoked(self.cert_path, self.chain_path)

        mock_revoke.assert_called_once_with(self.cert_path, self.chain_path, 'http://example.com')

    @mock.patch('certbot.ocsp._check_ocsp_response_signature')
    @mock.patch('certbot.ocsp.requests.post')
    @mock.patch('certbot.ocsp.ocsp.load_der_ocsp_response')
    def test_revoke(self, mock_ocsp_response, mock_post, _):
        mock_ocsp_response.return_value = mock.Mock(
            certificate_status=ocsp_lib.OCSPCertStatus.REVOKED)
        mock_post.return_value = mock.Mock(status_code=200)
        revoked = self.checker.ocsp_revoked(self.cert_path, self.chain_path)

        self.assertTrue(revoked)

    @mock.patch('certbot.ocsp._check_ocsp_response_signature')
    @mock.patch('certbot.ocsp.requests.post')
    @mock.patch('certbot.ocsp.ocsp.load_der_ocsp_response')
    def test_revoke_resiliency(self, mock_ocsp_response, mock_post, _):
        mock_ocsp_response.return_value = mock.Mock(
            certificate_status=ocsp_lib.OCSPCertStatus.REVOKED)
        mock_post.return_value = mock.Mock(status_code=400)
        revoked = self.checker.ocsp_revoked(self.cert_path, self.chain_path)

        self.assertFalse(revoked)

        mock_ocsp_response.return_value = mock.Mock(
            certificate_status=ocsp_lib.OCSPCertStatus.UNKNOWN)
        mock_post.return_value = mock.Mock(status_code=200)
        revoked = self.checker.ocsp_revoked(self.cert_path, self.chain_path)

        self.assertFalse(revoked)

        mock_ocsp_response.return_value = mock.Mock(
            certificate_status=ocsp_lib.OCSPCertStatus.REVOKED)
        mock_post.return_value = mock.Mock(status_code=200)
        with mock.patch('cryptography.x509.Extensions.get_extension_for_class',
                        side_effect=x509.ExtensionNotFound(
                            'Not found', x509.AuthorityInformationAccessOID.OCSP)):
            revoked = self.checker.ocsp_revoked(self.cert_path, self.chain_path)

        self.assertFalse(revoked)


# pylint: disable=line-too-long
openssl_confused = ("", """
/etc/letsencrypt/live/example.org/cert.pem: good
	This Update: Dec 17 00:00:00 2016 GMT
	Next Update: Dec 24 00:00:00 2016 GMT
""",
"""
Response Verify Failure
139903674214048:error:27069065:OCSP routines:OCSP_basic_verify:certificate verify error:ocsp_vfy.c:138:Verify error:unable to get local issuer certificate
""")

openssl_happy = ("blah.pem", """
blah.pem: good
	This Update: Dec 20 18:00:00 2016 GMT
	Next Update: Dec 27 18:00:00 2016 GMT
""",
"Response verify OK")

openssl_revoked = ("blah.pem", """
blah.pem: revoked
	This Update: Dec 20 01:00:00 2016 GMT
	Next Update: Dec 27 01:00:00 2016 GMT
	Revocation Time: Dec 20 01:46:34 2016 GMT
""",
"""Response verify OK""")

openssl_unknown = ("blah.pem", """
blah.pem: unknown
	This Update: Dec 20 18:00:00 2016 GMT
	Next Update: Dec 27 18:00:00 2016 GMT
""",
"Response verify OK")

openssl_broken = ("", "tentacles", "Response verify OK")

openssl_expired_ocsp = ("blah.pem", """
blah.pem: WARNING: Status times invalid.
140659132298912:error:2707307D:OCSP routines:OCSP_check_validity:status expired:ocsp_cl.c:372:
good
	This Update: Apr  6 00:00:00 2016 GMT
	Next Update: Apr 13 00:00:00 2016 GMT
""",
"""Response verify OK""")

openssl_expired_ocsp_revoked = ("blah.pem", """
blah.pem: WARNING: Status times invalid.
140659132298912:error:2707307D:OCSP routines:OCSP_check_validity:status expired:ocsp_cl.c:372:
revoked
	This Update: Apr  6 00:00:00 2016 GMT
	Next Update: Apr 13 00:00:00 2016 GMT
""",
"""Response verify OK""")

google_certificate = '''
-----BEGIN CERTIFICATE-----
MIIHQjCCBiqgAwIBAgIQCgYwQn9bvO1pVzllk7ZFHzANBgkqhkiG9w0BAQsFADB1
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMTQwMgYDVQQDEytEaWdpQ2VydCBTSEEyIEV4dGVuZGVk
IFZhbGlkYXRpb24gU2VydmVyIENBMB4XDTE4MDUwODAwMDAwMFoXDTIwMDYwMzEy
MDAwMFowgccxHTAbBgNVBA8MFFByaXZhdGUgT3JnYW5pemF0aW9uMRMwEQYLKwYB
BAGCNzwCAQMTAlVTMRkwFwYLKwYBBAGCNzwCAQITCERlbGF3YXJlMRAwDgYDVQQF
Ewc1MTU3NTUwMQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTEWMBQG
A1UEBxMNU2FuIEZyYW5jaXNjbzEVMBMGA1UEChMMR2l0SHViLCBJbmMuMRMwEQYD
VQQDEwpnaXRodWIuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
xjyq8jyXDDrBTyitcnB90865tWBzpHSbindG/XqYQkzFMBlXmqkzC+FdTRBYyneZ
w5Pz+XWQvL+74JW6LsWNc2EF0xCEqLOJuC9zjPAqbr7uroNLghGxYf13YdqbG5oj
/4x+ogEG3dF/U5YIwVr658DKyESMV6eoYV9mDVfTuJastkqcwero+5ZAKfYVMLUE
sMwFtoTDJFmVf6JlkOWwsxp1WcQ/MRQK1cyqOoUFUgYylgdh3yeCDPeF22Ax8AlQ
xbcaI+GwfQL1FB7Jy+h+KjME9lE/UpgV6Qt2R1xNSmvFCBWu+NFX6epwFP/JRbkM
fLz0beYFUvmMgLtwVpEPSwIDAQABo4IDeTCCA3UwHwYDVR0jBBgwFoAUPdNQpdag
re7zSmAKZdMh1Pj41g8wHQYDVR0OBBYEFMnCU2FmnV+rJfQmzQ84mqhJ6kipMCUG
A1UdEQQeMByCCmdpdGh1Yi5jb22CDnd3dy5naXRodWIuY29tMA4GA1UdDwEB/wQE
AwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwdQYDVR0fBG4wbDA0
oDKgMIYuaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL3NoYTItZXYtc2VydmVyLWcy
LmNybDA0oDKgMIYuaHR0cDovL2NybDQuZGlnaWNlcnQuY29tL3NoYTItZXYtc2Vy
dmVyLWcyLmNybDBLBgNVHSAERDBCMDcGCWCGSAGG/WwCATAqMCgGCCsGAQUFBwIB
FhxodHRwczovL3d3dy5kaWdpY2VydC5jb20vQ1BTMAcGBWeBDAEBMIGIBggrBgEF
BQcBAQR8MHowJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBS
BggrBgEFBQcwAoZGaHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0
U0hBMkV4dGVuZGVkVmFsaWRhdGlvblNlcnZlckNBLmNydDAMBgNVHRMBAf8EAjAA
MIIBfgYKKwYBBAHWeQIEAgSCAW4EggFqAWgAdgCkuQmQtBhYFIe7E6LMZ3AKPDWY
BPkb37jjd80OyA3cEAAAAWNBYm0KAAAEAwBHMEUCIQDRZp38cTWsWH2GdBpe/uPT
Wnsu/m4BEC2+dIcvSykZYgIgCP5gGv6yzaazxBK2NwGdmmyuEFNSg2pARbMJlUFg
U5UAdgBWFAaaL9fC7NP14b1Esj7HRna5vJkRXMDvlJhV1onQ3QAAAWNBYm0tAAAE
AwBHMEUCIQCi7omUvYLm0b2LobtEeRAYnlIo7n6JxbYdrtYdmPUWJQIgVgw1AZ51
vK9ENinBg22FPxb82TvNDO05T17hxXRC2IYAdgC72d+8H4pxtZOUI5eqkntHOFeV
CqtS6BqQlmQ2jh7RhQAAAWNBYm3fAAAEAwBHMEUCIQChzdTKUU2N+XcqcK0OJYrN
8EYynloVxho4yPk6Dq3EPgIgdNH5u8rC3UcslQV4B9o0a0w204omDREGKTVuEpxG
eOQwDQYJKoZIhvcNAQELBQADggEBAHAPWpanWOW/ip2oJ5grAH8mqQfaunuCVE+v
ac+88lkDK/LVdFgl2B6kIHZiYClzKtfczG93hWvKbST4NRNHP9LiaQqdNC17e5vN
HnXVUGw+yxyjMLGqkgepOnZ2Rb14kcTOGp4i5AuJuuaMwXmCo7jUwPwfLe1NUlVB
Kqg6LK0Hcq4K0sZnxE8HFxiZ92WpV2AVWjRMEc/2z2shNoDvxvFUYyY1Oe67xINk
myQKc+ygSBZzyLnXSFVWmHr3u5dcaaQGGAR42v6Ydr4iL38Hd4dOiBma+FXsXBIq
WUjbST4VXmdaol7uzFMojA4zkxQDZAvF5XgJlAFadfySna/teik=
-----END CERTIFICATE-----
'''

google_issuer_certificate = '''
-----BEGIN CERTIFICATE-----
MIIEXDCCA0SgAwIBAgINAeOpMBz8cgY4P5pTHTANBgkqhkiG9w0BAQsFADBMMSAw
HgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMjETMBEGA1UEChMKR2xvYmFs
U2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjAeFw0xNzA2MTUwMDAwNDJaFw0yMTEy
MTUwMDAwNDJaMFQxCzAJBgNVBAYTAlVTMR4wHAYDVQQKExVHb29nbGUgVHJ1c3Qg
U2VydmljZXMxJTAjBgNVBAMTHEdvb2dsZSBJbnRlcm5ldCBBdXRob3JpdHkgRzMw
ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDKUkvqHv/OJGuo2nIYaNVW
XQ5IWi01CXZaz6TIHLGp/lOJ+600/4hbn7vn6AAB3DVzdQOts7G5pH0rJnnOFUAK
71G4nzKMfHCGUksW/mona+Y2emJQ2N+aicwJKetPKRSIgAuPOB6Aahh8Hb2XO3h9
RUk2T0HNouB2VzxoMXlkyW7XUR5mw6JkLHnA52XDVoRTWkNty5oCINLvGmnRsJ1z
ouAqYGVQMc/7sy+/EYhALrVJEA8KbtyX+r8snwU5C1hUrwaW6MWOARa8qBpNQcWT
kaIeoYvy/sGIJEmjR0vFEwHdp1cSaWIr6/4g72n7OqXwfinu7ZYW97EfoOSQJeAz
AgMBAAGjggEzMIIBLzAOBgNVHQ8BAf8EBAMCAYYwHQYDVR0lBBYwFAYIKwYBBQUH
AwEGCCsGAQUFBwMCMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFHfCuFCa
Z3Z2sS3ChtCDoH6mfrpLMB8GA1UdIwQYMBaAFJviB1dnHB7AagbeWbSaLd/cGYYu
MDUGCCsGAQUFBwEBBCkwJzAlBggrBgEFBQcwAYYZaHR0cDovL29jc3AucGtpLmdv
b2cvZ3NyMjAyBgNVHR8EKzApMCegJaAjhiFodHRwOi8vY3JsLnBraS5nb29nL2dz
cjIvZ3NyMi5jcmwwPwYDVR0gBDgwNjA0BgZngQwBAgIwKjAoBggrBgEFBQcCARYc
aHR0cHM6Ly9wa2kuZ29vZy9yZXBvc2l0b3J5LzANBgkqhkiG9w0BAQsFAAOCAQEA
HLeJluRT7bvs26gyAZ8so81trUISd7O45skDUmAge1cnxhG1P2cNmSxbWsoiCt2e
ux9LSD+PAj2LIYRFHW31/6xoic1k4tbWXkDCjir37xTTNqRAMPUyFRWSdvt+nlPq
wnb8Oa2I/maSJukcxDjNSfpDh/Bd1lZNgdd/8cLdsE3+wypufJ9uXO1iQpnh9zbu
FIwsIONGl1p3A8CgxkqI/UAih3JaGOqcpcdaCIzkBaR9uYQ1X4k2Vg5APRLouzVy
7a8IVk6wuy6pm+T7HT4LY8ibS5FEZlfAFLSW8NwsVz9SBK2Vqn1N0PIMn5xA6NZV
c7o835DLAFshEWfC7TIe3g==
-----END CERTIFICATE-----
'''

if __name__ == '__main__':
    unittest.main()  # pragma: no cover
