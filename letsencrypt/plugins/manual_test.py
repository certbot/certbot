"""Tests for letsencrypt.plugins.manual."""
import signal
import unittest

import mock

from acme import challenges
from acme import jose

from letsencrypt import achallenges
from letsencrypt import errors

from letsencrypt.tests import acme_util
from letsencrypt.tests import test_util


KEY = jose.JWKRSA.load(test_util.load_vector("rsa512_key.pem"))


class ManualAuthenticatorTest(unittest.TestCase):
    """Tests for letsencrypt.plugins.manual.ManualAuthenticator."""

    def setUp(self):
        from letsencrypt.plugins.manual import ManualAuthenticator
        self.config = mock.MagicMock(
            no_simple_http_tls=True, simple_http_port=4430,
            manual_test_mode=False)
        self.auth = ManualAuthenticator(config=self.config, name="manual")
        self.achalls = [achallenges.SimpleHTTP(
            challb=acme_util.SIMPLE_HTTP_P, domain="foo.com", account_key=KEY)]

        config_test_mode = mock.MagicMock(
            no_simple_http_tls=True, simple_http_port=4430,
            manual_test_mode=True)
        self.auth_test_mode = ManualAuthenticator(
            config=config_test_mode, name="manual")

    def test_more_info(self):
        self.assertTrue(isinstance(self.auth.more_info(), str))

    def test_get_chall_pref(self):
        self.assertTrue(all(issubclass(pref, challenges.Challenge)
                            for pref in self.auth.get_chall_pref("foo.com")))

    def test_perform_empty(self):
        self.assertEqual([], self.auth.perform([]))

    @mock.patch("letsencrypt.plugins.manual.sys.stdout")
    @mock.patch("letsencrypt.plugins.manual.os.urandom")
    @mock.patch("acme.challenges.SimpleHTTPResponse.simple_verify")
    @mock.patch("__builtin__.raw_input")
    def test_perform(self, mock_raw_input, mock_verify, mock_urandom,
                     mock_stdout):
        mock_urandom.side_effect = nonrandom_urandom
        mock_verify.return_value = True

        resp = challenges.SimpleHTTPResponse(tls=False)
        self.assertEqual([resp], self.auth.perform(self.achalls))
        self.assertEqual(1, mock_raw_input.call_count)
        mock_verify.assert_called_with(
            self.achalls[0].challb.chall, "foo.com", KEY.public_key(), 4430)

        message = mock_stdout.write.mock_calls[0][1][0]
        self.assertEqual(message, """\
Make sure your web server displays the following content at
http://foo.com/.well-known/acme-challenge/ZXZhR3hmQURzNnBTUmIyTEF2OUlaZjE3RHQzanV4R0orUEN0OTJ3citvQQ before continuing:

{"header": {"alg": "RS256", "jwk": {"e": "AQAB", "kty": "RSA", "n": "rHVztFHtH92ucFJD_N_HW9AsdRsUuHUBBBDlHwNlRd3fp580rv2-6QWE30cWgdmJS86ObRz6lUTor4R0T-3C5Q"}}, "payload": "eyJ0bHMiOiBmYWxzZSwgInRva2VuIjogIlpYWmhSM2htUVVSek5uQlRVbUl5VEVGMk9VbGFaakUzUkhRemFuVjRSMG9yVUVOME9USjNjaXR2UVEiLCAidHlwZSI6ICJzaW1wbGVIdHRwIn0", "signature": "jFPJFC-2eRyBw7Sl0wyEBhsdvRZtKk8hc6HykEPAiofZlIwdIu76u2xHqMVZWSZdpxwMNUnnawTEAqgMWFydMA"}

Content-Type header MUST be set to application/jose+json.

If you don\'t have HTTP server configured, you can run the following
command on the target server (as root):

mkdir -p /tmp/letsencrypt/public_html/.well-known/acme-challenge
cd /tmp/letsencrypt/public_html
echo -n \'{"header": {"alg": "RS256", "jwk": {"e": "AQAB", "kty": "RSA", "n": "rHVztFHtH92ucFJD_N_HW9AsdRsUuHUBBBDlHwNlRd3fp580rv2-6QWE30cWgdmJS86ObRz6lUTor4R0T-3C5Q"}}, "payload": "eyJ0bHMiOiBmYWxzZSwgInRva2VuIjogIlpYWmhSM2htUVVSek5uQlRVbUl5VEVGMk9VbGFaakUzUkhRemFuVjRSMG9yVUVOME9USjNjaXR2UVEiLCAidHlwZSI6ICJzaW1wbGVIdHRwIn0", "signature": "jFPJFC-2eRyBw7Sl0wyEBhsdvRZtKk8hc6HykEPAiofZlIwdIu76u2xHqMVZWSZdpxwMNUnnawTEAqgMWFydMA"}\' > .well-known/acme-challenge/ZXZhR3hmQURzNnBTUmIyTEF2OUlaZjE3RHQzanV4R0orUEN0OTJ3citvQQ
# run only once per server:
$(command -v python2 || command -v python2.7 || command -v python2.6) -c \\
"import BaseHTTPServer, SimpleHTTPServer; \\
SimpleHTTPServer.SimpleHTTPRequestHandler.extensions_map = {\'\': \'application/jose+json\'}; \\
s = BaseHTTPServer.HTTPServer((\'\', 4430), SimpleHTTPServer.SimpleHTTPRequestHandler); \\
s.serve_forever()" \n""")
        #self.assertTrue(validation in message)

        mock_verify.return_value = False
        self.assertEqual([None], self.auth.perform(self.achalls))

    @mock.patch("letsencrypt.plugins.manual.subprocess.Popen", autospec=True)
    def test_perform_test_command_oserror(self, mock_popen):
        mock_popen.side_effect = OSError
        self.assertEqual([False], self.auth_test_mode.perform(self.achalls))

    @mock.patch("letsencrypt.plugins.manual.socket.socket", autospec=True)
    @mock.patch("letsencrypt.plugins.manual.time.sleep", autospec=True)
    @mock.patch("letsencrypt.plugins.manual.subprocess.Popen", autospec=True)
    def test_perform_test_command_run_failure(
            self, mock_popen, unused_mock_sleep, unused_mock_socket):
        mock_popen.poll.return_value = 10
        mock_popen.return_value.pid = 1234
        self.assertRaises(
            errors.Error, self.auth_test_mode.perform, self.achalls)

    @mock.patch("letsencrypt.plugins.manual.socket.socket", autospec=True)
    @mock.patch("letsencrypt.plugins.manual.time.sleep", autospec=True)
    @mock.patch("acme.challenges.SimpleHTTPResponse.simple_verify",
                autospec=True)
    @mock.patch("letsencrypt.plugins.manual.subprocess.Popen", autospec=True)
    def test_perform_test_mode(self, mock_popen, mock_verify, mock_sleep,
                               mock_socket):
        mock_popen.return_value.poll.side_effect = [None, 10]
        mock_popen.return_value.pid = 1234
        mock_verify.return_value = False
        self.assertEqual([False], self.auth_test_mode.perform(self.achalls))
        self.assertEqual(1, mock_sleep.call_count)
        self.assertEqual(1, mock_socket.call_count)

    def test_cleanup_test_mode_already_terminated(self):
        # pylint: disable=protected-access
        self.auth_test_mode._httpd = httpd = mock.Mock()
        httpd.poll.return_value = 0
        self.auth_test_mode.cleanup(self.achalls)

    @mock.patch("letsencrypt.plugins.manual.os.killpg", autospec=True)
    def test_cleanup_test_mode_kills_still_running(self, mock_killpg):
        # pylint: disable=protected-access
        self.auth_test_mode._httpd = httpd = mock.Mock(pid=1234)
        httpd.poll.return_value = None
        self.auth_test_mode.cleanup(self.achalls)
        mock_killpg.assert_called_once_with(1234, signal.SIGTERM)


def nonrandom_urandom(num_bytes):
    """Returns a string of length num_bytes"""
    return "x" * num_bytes


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
