"""Tests for letsencrypt.plugins.manual."""
import unittest

import mock

from acme import challenges
from acme import jose

from letsencrypt import achallenges
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

def nonrandom_urandom(num_bytes):
    """Returns a string of length num_bytes"""
    return "x" * num_bytes


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
