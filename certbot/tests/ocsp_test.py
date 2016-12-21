
"""Tests for hooks.py"""
# pylint: disable=protected-access

import os
import unittest

import mock

from certbot import errors
from certbot import hooks

out = """Missing = in header key=value
ocsp: Use -help for summary.
"""

class OCSPTest(unittest.TestCase):

    _multiprocess_can_split_ = True

    def setUp(self):
        from certbot import ocsp
        self.config = mock.MagicMock()
        self.checker = ocsp.RevocationChecker(self.config)

    def tearDown(self):
        pass

    @mock.patch('certbot.ocsp.logging.info')
    @mock.patch('certbot.ocsp.Popen')
    @mock.patch('certbot.util.exe_exists')
    def test_init(self, mock_exists, mock_popen, mock_log):
        mock_communicate = mock.MagicMock()
        mock_communicate.communicate.return_value = (None, out)
        mock_popen.return_value = mock_communicate
        mock_exists.return_value = True

        from certbot import ocsp
        checker = ocsp.RevocationChecker(self.config)
        self.assertEqual(mock_popen.call_count, 1)
        self.assertEqual(checker.host_args("x"), ["Host=x"])

        mock_communicate.communicate.return_value = (None, out.partition("\n")[2])
        checker = ocsp.RevocationChecker(self.config)
        self.assertEqual(checker.host_args("x"), ["Host", "x"])
        self.assertEqual(checker.broken, False)

        mock_exists.return_value = False
        mock_popen.call_count = 0
        checker = ocsp.RevocationChecker(self.config)
        self.assertEqual(mock_popen.call_count, 0)
        self.assertEqual(mock_log.call_count, 1)
        self.assertEqual(checker.broken, True)

    def test_ocsp_status(self):
        from certbot import ocsp
        checker = self.checker
        checker.check_ocsp = mock.MagicMock()
        checker.check_ocsp.return_value = "octopus found in certificate"

        checker.config.check_ocsp = "never"
        self.assertEqual(checker.ocsp_status("a", "a", "xyz"), "xyz")
        self.assertEqual(checker.ocsp_status("a", "a", ""), "")
        self.assertEqual(checker.check_ocsp.call_count, 0)

        checker.config.check_ocsp = "lazy"
        self.assertEqual(checker.ocsp_status("a", "a", "xyz"), "xyz")
        self.assertEqual(checker.check_ocsp.call_count, 0)
        self.assertEqual(checker.ocsp_status("a", "a", ""), "INVALID: REVOKED")

        checker.config.check_ocsp = "always"
        self.assertEqual(checker.ocsp_status("a", "a", "xyz"), "xyz,REVOKED")
        checker.check_ocsp.return_value = ""
        self.assertEqual(checker.ocsp_status("a", "a", "xyz"), "xyz")
        
            
    @mock.patch('certbot.ocsp.logger.debug')
    @mock.patch('certbot.ocsp.logger.info')
    @mock.patch('certbot.util.run_script')
    def test_determine_ocsp_server(self, mock_run, mock_info, mock_debug):
        uri = "http://ocsp.stg-int-x1.letsencrypt.org/"
        host = "ocsp.stg-int-x1.letsencrypt.org"
        mock_run.return_value = uri, ""
        self.assertEquals(self.checker.determine_ocsp_server("beep"), (uri, host))
        mock_run.return_value = "ftp:/" + host + "/", ""
        self.assertEquals(self.checker.determine_ocsp_server("beep"), (None, None))
        self.assertEquals(mock_info.call_count, 1)

        c = "confusion"
        mock_run.side_effect = errors.SubprocessError(c)
        self.assertEquals(self.checker.determine_ocsp_server("beep"), (None, None))
        self.assertTrue(c in mock_debug.call_args[0][1])

    @mock.patch('certbot.ocsp.logger')
    @mock.patch('certbot.util.run_script')
    def test_translate_ocsp(self, mock_run, mock_log):
        # pylint: disable=protected-access 
        mock_run.return_value = openssl_confused
        from certbot import ocsp
        self.assertEquals(ocsp._translate_ocsp_query(*openssl_happy), "")
        self.assertEquals(ocsp._translate_ocsp_query(*openssl_confused), "")
        self.assertEquals(mock_log.debug.call_count, 1)
        self.assertEquals(mock_log.warn.call_count, 0)
        self.assertEquals(ocsp._translate_ocsp_query(*openssl_broken), "")
        self.assertEquals(mock_log.warn.call_count, 1)
        self.assertEquals(ocsp._translate_ocsp_query(*openssl_revoked), "REVOKED")


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

openssl_broken = ("", "tentacles", "Response verify OK")

if __name__ == '__main__':
    unittest.main()  # pragma: no cover
