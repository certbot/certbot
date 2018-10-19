"""Tests for ocsp.py"""
# pylint: disable=protected-access

import mock
import os
import unittest

from certbot import errors
from certbot import ocsp

from certbot.tests import util

from cryptography.x509.oid import AuthorityInformationAccessOID

out = """Missing = in header key=value
ocsp: Use -help for summary.
"""

class OCSPTest(unittest.TestCase):


    def setUp(self):
        with mock.patch('certbot.ocsp.Popen') as mock_popen:
            with mock.patch('certbot.util.exe_exists') as mock_exists:
                mock_communicate = mock.MagicMock()
                mock_communicate.communicate.return_value = (None, out)
                mock_popen.return_value = mock_communicate
                mock_exists.return_value = True
                self.checker = ocsp.RevocationChecker()

    def tearDown(self):
        pass

    def _call_mock_cert(self, func, *args, **kwargs):
        """Helper method that uses mocked certificate object for testing"""

        ocsp_ext = mock.MagicMock()
        ocsp_ext.access_method = AuthorityInformationAccessOID.OCSP
        ocsp_ext.access_location.value = "http://ocsp.stg-int-x1.letsencrypt.org/"
        mock_cert = mock.MagicMock()
        mock_cert.extensions.get_extension_for_oid.return_value = mock.MagicMock(value=[ocsp_ext])
        with mock.patch('certbot.crypto_util.load_cert') as load_cert:
            load_cert.return_value = mock_cert
            return func(*args, **kwargs)

    @mock.patch('certbot.ocsp.logger.info')
    @mock.patch('certbot.ocsp.Popen')
    @mock.patch('certbot.util.exe_exists')
    def test_init(self, mock_exists, mock_popen, mock_log):
        mock_communicate = mock.MagicMock()
        mock_communicate.communicate.return_value = (None, out)
        mock_popen.return_value = mock_communicate
        mock_exists.return_value = True

        checker = ocsp.RevocationChecker()
        self.assertEqual(mock_popen.call_count, 1)
        self.assertEqual(checker.host_args("x"), ["Host=x"])

        mock_communicate.communicate.return_value = (None, out.partition("\n")[2])
        checker = ocsp.RevocationChecker()
        self.assertEqual(checker.host_args("x"), ["Host", "x"])
        self.assertEqual(checker.broken, False)

        mock_exists.return_value = False
        mock_popen.call_count = 0
        checker = ocsp.RevocationChecker()
        self.assertEqual(mock_popen.call_count, 0)
        self.assertEqual(mock_log.call_count, 1)
        self.assertEqual(checker.broken, True)

    @mock.patch('certbot.ocsp.RevocationChecker.determine_ocsp_server')
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


    @mock.patch('certbot.ocsp.logger.info')
    def test_determine_ocsp_server(self, mock_info):
        uri = "http://ocsp.stg-int-x1.letsencrypt.org/"
        host = "ocsp.stg-int-x1.letsencrypt.org"
        self.assertEqual(
            self._call_mock_cert(self.checker.determine_ocsp_server, "path_to_cert"),
            (uri, host))
        self.assertEqual(self.checker.determine_ocsp_server("beep"), (None, None))
        self.assertEqual(mock_info.call_count, 1)

    @mock.patch('certbot.ocsp.logger')
    @mock.patch('certbot.util.run_script')
    def test_translate_ocsp(self, mock_run, mock_log):
        # pylint: disable=protected-access,star-args
        mock_run.return_value = openssl_confused
        self.assertEqual(ocsp._translate_ocsp_query(*openssl_happy), False)
        self.assertEqual(ocsp._translate_ocsp_query(*openssl_confused), False)
        self.assertEqual(mock_log.debug.call_count, 1)
        self.assertEqual(mock_log.warn.call_count, 0)
        mock_log.debug.call_count = 0
        self.assertEqual(ocsp._translate_ocsp_query(*openssl_unknown), False)
        self.assertEqual(mock_log.debug.call_count, 1)
        self.assertEqual(mock_log.warn.call_count, 0)
        self.assertEqual(ocsp._translate_ocsp_query(*openssl_expired_ocsp), False)
        self.assertEqual(mock_log.debug.call_count, 2)
        self.assertEqual(ocsp._translate_ocsp_query(*openssl_broken), False)
        self.assertEqual(mock_log.warn.call_count, 1)
        mock_log.info.call_count = 0
        self.assertEqual(ocsp._translate_ocsp_query(*openssl_revoked), True)
        self.assertEqual(mock_log.info.call_count, 0)
        self.assertEqual(ocsp._translate_ocsp_query(*openssl_expired_ocsp_revoked), True)
        self.assertEqual(mock_log.info.call_count, 1)


class OCSPResponseHandlerTest(util.TempDirTestCase):
    """Tests for certbot.ocsp.OCSPResponseHandler"""

    def setUp(self):
        super(OCSPResponseHandlerTest, self).setUp()
        self.handler = ocsp.OCSPResponseHandler("blah.pem", "chainpath")
        self.response_filep = os.path.join(self.tempdir, "ocsp_response")

    def _call_mocked(self, output, func, *args, **kwargs):
        """Helper method to mock subprocess.Popen and reading OCSP url from cert"""
        # openssl call creates the output file
        open(self.response_filep, 'w').close()
        with mock.patch('certbot.util.run_script') as mock_popen:
            mock_popen.return_value = output, ""
            with mock.patch('certbot.ocsp.OCSPBase.determine_ocsp_server') as mock_url:
                mock_url.return_value = "http://ocsp.example.com", ""
                return func(*args, **kwargs)

    @mock.patch("certbot.ocsp.logger.info")
    def test_queryfail(self, mock_log):
        with mock.patch('certbot.util.run_script', side_effect=errors.SubprocessError):
            with mock.patch('certbot.ocsp.OCSPBase.determine_ocsp_server') as mock_url:
                mock_url.return_value = "http://ocsp.example.com", ""
                self.assertFalse(self.handler.ocsp_request_to_file(self.response_filep))
                self.assertTrue(mock_log.called)
                self.assertEqual(mock_log.call_args[0][0],
                                 'OCSP check failed for %s (are we offline?)')

    def test_queryunsuccessful(self):
        self.assertRaises(errors.OCSPRequestError,
                        self._call_mocked,
                        "OCSP Response Status: nope",
                        self.handler.ocsp_request_to_file,
                        self.response_filep)

    def test_revoked(self):
        self.assertRaises(errors.OCSPRevokedError,
                        self._call_mocked,
                        openssl_revoked[1],
                        self.handler.ocsp_request_to_file,
                        self.response_filep)

    def test_nogood(self):
        self.assertFalse(self._call_mocked(
            openssl_unknown[1],
            self.handler.ocsp_request_to_file,
            self.response_filep))

    def test_success_full(self):
        self.assertTrue(self._call_mocked(
            openssl_full_success,
            self.handler.ocsp_request_to_file,
            self.response_filep))


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
OCSP Response Data:
    OCSP Response Status: successful (0x0)
blah.pem: good
	This Update: Dec 20 18:00:00 2016 GMT
	Next Update: Dec 27 18:00:00 2016 GMT
""",
"Response verify OK")

openssl_revoked = ("blah.pem", """
OCSP Response Data:
    OCSP Response Status: successful (0x0)
blah.pem: revoked
	This Update: Dec 20 01:00:00 2016 GMT
	Next Update: Dec 27 01:00:00 2016 GMT
	Revocation Time: Dec 20 01:46:34 2016 GMT
""",
"""Response verify OK""")

openssl_unknown = ("blah.pem", """
OCSP Response Data:
    OCSP Response Status: successful (0x0)
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

openssl_full_success = """
OCSP Request Data:
    Version: 1 (0x0)
    Requestor List:
        Certificate ID:
          Hash Algorithm: sha1
          Issuer Name Hash: C29C130A07D1FF36475F8766B701C13205DF6527
          Issuer Key Hash: C0CC0346B95820CC5C7270F3E12ECB20A6F5683A
          Serial Number: FA185757440D467FCCBA5D832824354BD74C
OCSP Response Data:
    OCSP Response Status: successful (0x0)
    Response Type: Basic OCSP Response
    Version: 1 (0x0)
    Responder Id: CN = Fake LE Intermediate X1
    Produced At: Oct 18 09:53:00 2018 GMT
    Responses:
    Certificate ID:
      Hash Algorithm: sha1
      Issuer Name Hash: C29C130A07D1FF36475F8766B701C13205DF6527
      Issuer Key Hash: C0CC0346B95820CC5C7270F3E12ECB20A6F5683A
      Serial Number: FA185757440D467FCCBA5D832824354BD74C
    Cert Status: good
    This Update: Oct 18 09:00:00 2018 GMT
    Next Update: Oct 25 09:00:00 2018 GMT

    Signature Algorithm: sha256WithRSAEncryption
         a1:15:14:c9:53:e0:5d:3d:fb:79:f6:1e:a4:be:a6:b3:bd:52:
         59:5e:b0:a9:cb:8e:3b:65:e6:9a:cc:cc:5d:45:64:d9:64:5d:
         a2:1c:c7:71:aa:94:27:bf:ee:9d:2c:53:70:3b:66:c7:41:d4:
         78:7e:cb:b7:c7:72:36:aa:c6:d3:a6:50:c6:4a:e4:d4:16:c8:
         34:26:57:f8:ee:10:d3:ea:2d:6e:2b:e3:54:92:c7:bd:00:84:
         30:03:cc:62:cd:f4:48:71:2c:1a:3f:0c:b9:a8:42:3e:60:83:
         dc:c8:27:41:54:e3:f6:5a:a5:b6:00:a4:d4:30:48:e5:bf:d6:
         55:98:02:a3:95:c9:04:08:af:23:f9:3c:bc:68:57:d5:13:a0:
         63:2d:14:9f:72:f1:a6:06:28:98:76:26:04:c8:9f:2e:1c:e8:
         f3:be:44:64:74:9c:8b:72:94:2f:e5:73:bd:38:99:77:b3:fc:
         bf:10:4e:d4:87:a1:0f:9f:2b:02:fa:6a:eb:67:e7:4c:fc:ef:
         32:29:e6:f7:8a:ad:56:7b:a7:a7:c0:0e:95:01:46:df:98:1e:
         4a:2b:72:99:14:96:06:a8:fc:59:c8:9b:3d:e0:e4:4e:8d:f5:
         aa:90:1a:db:39:44:04:f0:ef:34:6a:90:cb:48:38:fe:ec:34:
         77:78:97:56
Response verify OK
blah.pem: good
	This Update: Oct 18 09:00:00 2018 GMT
	Next Update: Oct 25 09:00:00 2018 GMT
"""

if __name__ == '__main__':
    unittest.main()  # pragma: no cover
