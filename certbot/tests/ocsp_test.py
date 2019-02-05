"""Tests for ocsp.py"""
# pylint: disable=protected-access
import unittest
from datetime import datetime, timedelta

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes  # type: ignore
from cryptography.exceptions import UnsupportedAlgorithm, InvalidSignature
from cryptography import x509
try:
    # Only cryptography>=2.5 has ocsp module
    # and signature_hash_algorithm attribute in OCSPResponse class
    from cryptography.x509 import ocsp as ocsp_lib  # pylint: disable=import-error
    getattr(ocsp_lib.OCSPResponse, 'signature_hash_algorithm')
except (ImportError, AttributeError):  # pragma: no cover
    ocsp_lib = None  # type: ignore
import mock

from certbot import errors
from certbot.tests import util as test_util

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

    @mock.patch('certbot.ocsp._determine_ocsp_server')
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
        cert_path = test_util.vector_path('google_certificate.pem')

        from certbot import ocsp
        result = ocsp._determine_ocsp_server(cert_path)
        self.assertEqual(('http://ocsp.digicert.com', 'ocsp.digicert.com'), result)

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
                 reason='This class tests functionalities available only on cryptography>=2.5.0')
class OSCPTestCryptography(unittest.TestCase):
    """
    OCSP revokation tests using Cryptography >= 2.4.0
    """

    def setUp(self):
        from certbot import ocsp
        self.checker = ocsp.RevocationChecker()
        self.cert_path = test_util.vector_path('google_certificate.pem')
        self.chain_path = test_util.vector_path('google_issuer_certificate.pem')

    @mock.patch('certbot.ocsp._determine_ocsp_server')
    @mock.patch('certbot.ocsp._check_ocsp_cryptography')
    def test_ensure_cryptography_toggled(self, mock_revoke, mock_determine):
        mock_determine.return_value = ('http://example.com', 'example.com')
        self.checker.ocsp_revoked(self.cert_path, self.chain_path)

        mock_revoke.assert_called_once_with(self.cert_path, self.chain_path, 'http://example.com')

    @mock.patch('certbot.ocsp.requests.post')
    @mock.patch('certbot.ocsp.ocsp.load_der_ocsp_response')
    def test_revoke(self, mock_ocsp_response, mock_post):
        with mock.patch('certbot.ocsp.crypto_util.verify_signed_payload'):
            mock_ocsp_response.return_value = _construct_mock_ocsp_response(
                ocsp_lib.OCSPCertStatus.REVOKED, ocsp_lib.OCSPResponseStatus.SUCCESSFUL)
            mock_post.return_value = mock.Mock(status_code=200)
            revoked = self.checker.ocsp_revoked(self.cert_path, self.chain_path)

        self.assertTrue(revoked)

    @mock.patch('certbot.ocsp.crypto_util.verify_signed_payload')
    @mock.patch('certbot.ocsp.requests.post')
    @mock.patch('certbot.ocsp.ocsp.load_der_ocsp_response')
    def test_revoke_resiliency(self, mock_ocsp_response, mock_post, mock_check):
        # Server return an invalid HTTP response
        mock_ocsp_response.return_value = _construct_mock_ocsp_response(
            ocsp_lib.OCSPCertStatus.UNKNOWN, ocsp_lib.OCSPResponseStatus.SUCCESSFUL)
        mock_post.return_value = mock.Mock(status_code=400)
        revoked = self.checker.ocsp_revoked(self.cert_path, self.chain_path)

        self.assertFalse(revoked)

        # OCSP response in invalid
        mock_ocsp_response.return_value = _construct_mock_ocsp_response(
            ocsp_lib.OCSPCertStatus.UNKNOWN, ocsp_lib.OCSPResponseStatus.UNAUTHORIZED)
        mock_post.return_value = mock.Mock(status_code=200)
        revoked = self.checker.ocsp_revoked(self.cert_path, self.chain_path)

        self.assertFalse(revoked)

        # OCSP response is valid, but certificate status is unknown
        mock_ocsp_response.return_value = _construct_mock_ocsp_response(
            ocsp_lib.OCSPCertStatus.UNKNOWN, ocsp_lib.OCSPResponseStatus.SUCCESSFUL)
        mock_post.return_value = mock.Mock(status_code=200)
        revoked = self.checker.ocsp_revoked(self.cert_path, self.chain_path)

        self.assertFalse(revoked)

        # The OCSP response says that the certificate is revoked, but certificate
        # does not contain the OCSP extension.
        mock_ocsp_response.return_value = _construct_mock_ocsp_response(
            ocsp_lib.OCSPCertStatus.UNKNOWN, ocsp_lib.OCSPResponseStatus.SUCCESSFUL)
        mock_post.return_value = mock.Mock(status_code=200)
        with mock.patch('cryptography.x509.Extensions.get_extension_for_class',
                        side_effect=x509.ExtensionNotFound(
                            'Not found', x509.AuthorityInformationAccessOID.OCSP)):
            revoked = self.checker.ocsp_revoked(self.cert_path, self.chain_path)

        self.assertFalse(revoked)

        # Valid response, OCSP extension is present,
        # but OCSP response uses an unsupported signature.
        mock_ocsp_response.return_value = _construct_mock_ocsp_response(
            ocsp_lib.OCSPCertStatus.REVOKED, ocsp_lib.OCSPResponseStatus.SUCCESSFUL)
        mock_post.return_value = mock.Mock(status_code=200)
        mock_check.side_effect = UnsupportedAlgorithm('foo')
        revoked = self.checker.ocsp_revoked(self.cert_path, self.chain_path)

        self.assertFalse(revoked)

        # And now, the signature itself is invalid.
        mock_ocsp_response.return_value = _construct_mock_ocsp_response(
            ocsp_lib.OCSPCertStatus.REVOKED, ocsp_lib.OCSPResponseStatus.SUCCESSFUL)
        mock_post.return_value = mock.Mock(status_code=200)
        mock_check.side_effect = InvalidSignature('foo')
        revoked = self.checker.ocsp_revoked(self.cert_path, self.chain_path)

        self.assertFalse(revoked)

        # Finally, assertion error on OCSP response validity
        mock_ocsp_response.return_value = _construct_mock_ocsp_response(
            ocsp_lib.OCSPCertStatus.REVOKED, ocsp_lib.OCSPResponseStatus.SUCCESSFUL)
        mock_post.return_value = mock.Mock(status_code=200)
        mock_check.side_effect = AssertionError('foo')
        revoked = self.checker.ocsp_revoked(self.cert_path, self.chain_path)

        self.assertFalse(revoked)


def _construct_mock_ocsp_response(certificate_status, response_status):
    cert = x509.load_pem_x509_certificate(
        test_util.load_vector('google_certificate.pem'), default_backend())
    issuer = x509.load_pem_x509_certificate(
        test_util.load_vector('google_issuer_certificate.pem'), default_backend())
    builder = ocsp_lib.OCSPRequestBuilder()
    builder = builder.add_certificate(cert, issuer, hashes.SHA1())
    request = builder.build()

    return mock.Mock(
        response_status=response_status,
        certificate_status=certificate_status,
        serial_number=request.serial_number,
        issuer_key_hash=request.issuer_key_hash,
        issuer_name_hash=request.issuer_name_hash,
        hash_algorithm=hashes.SHA1(),
        next_update=datetime.now() + timedelta(days=1),
        this_update=datetime.now() - timedelta(days=1),
        signature_algorithm_oid=x509.oid.SignatureAlgorithmOID.RSA_WITH_SHA1,
    )


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


if __name__ == '__main__':
    unittest.main()  # pragma: no cover
