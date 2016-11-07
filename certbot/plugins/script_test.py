"""Tests for certbot.plugins.manual."""
import os
import tempfile
import unittest

import mock

from acme import challenges
from acme import jose

from certbot import achallenges
from certbot import errors

from certbot.tests import acme_util
from certbot.tests import test_util


KEY = jose.JWKRSA.load(test_util.load_vector("rsa512_key.pem"))


class AuthenticatorTest(unittest.TestCase):
    """Tests for certbot.plugins.script.Authenticator."""

    def setUp(self):
        from certbot.plugins.script import Authenticator
        self.auth_return_value = "return from auth\n"
        self.script_nonexec = create_script(b'# empty')
        self.script_exec = create_script_exec(b'echo "return from auth\n"')
        self.config = mock.MagicMock(
            script_auth=self.script_exec,
            script_cleanup=self.script_exec,
            pref_challs=[challenges.Challenge.TYPES["http-01"],
                         challenges.Challenge.TYPES["dns-01"],
                         challenges.Challenge.TYPES["tls-sni-01"]])

        self.tlssni_config = mock.MagicMock(
            script_auth=self.script_exec,
            script_cleanup=self.script_exec,
            pref_challs=[challenges.Challenge.TYPES["tls-sni-01"]])

        self.nochall_config = mock.MagicMock(
            script_auth=self.script_exec,
            script_cleanup=self.script_exec,
            )

        self.default = Authenticator(config=self.config, name="script")
        self.onlytlssni = Authenticator(config=self.tlssni_config,
                                        name="script")
        self.nochall = Authenticator(config=self.nochall_config,
                                     name="script")

        self.http01 = achallenges.KeyAuthorizationAnnotatedChallenge(
            challb=acme_util.HTTP01_P, domain="foo.com", account_key=KEY)
        self.dns01 = achallenges.KeyAuthorizationAnnotatedChallenge(
            challb=acme_util.DNS01_P, domain="foo.com", account_key=KEY)

        self.achalls = [self.http01, self.dns01]

    def tearDown(self):
        os.remove(self.script_exec)
        os.remove(self.script_nonexec)

    def test_prepare_normal(self):
        """Test prepare with typical configuration"""
        from certbot.plugins.script import Authenticator
        # Erroring combinations in from of (auth_script, cleanup_script, error)
        for v in [("/NONEXISTENT/script.sh", "/NONEXISTENT/script.sh",
                   errors.HookCommandNotFound),
                  (self.script_nonexec, "/NONEXISTENT/script.sh",
                   errors.HookCommandNotFound),
                  (self.script_exec, "/NONEXISTENT/script.sh",
                   errors.HookCommandNotFound),
                  ("/NONEXISTENT/script.sh", self.script_nonexec,
                   errors.HookCommandNotFound),
                  ("/NONEXISTENT/script.sh", self.script_exec,
                   errors.HookCommandNotFound),
                  (None, self.script_exec,
                   errors.PluginError)]:
            testconf = mock.MagicMock(
                script_auth=v[0],
                script_cleanup=v[1],
                pref_challs=[challenges.Challenge.TYPES["http-01"]])
            testauth = Authenticator(config=testconf, name="script")
            self.assertRaises(v[2], testauth.prepare)

        # This should not error
        self.default.prepare()
        self.assertEqual(len(self.default.challenges), 2)

    def test_prepare_tlssni(self):
        """Test for provided, but unsupported challenge type"""
        self.assertRaises(errors.PluginError, self.onlytlssni.prepare)

    def test_prepare_nochall(self):
        """Test for default challenge"""
        self.nochall.prepare()
        self.assertEqual(len(self.nochall.challenges), 1)

    def test_more_info(self):
        self.assertTrue(isinstance(self.default.more_info(), str))

    def test_get_chall_pref(self):
        self.default.prepare()
        self.assertTrue(all(issubclass(pref, challenges.Challenge)
                            for pref in self.default.get_chall_pref(
                                "foo.com")))

    def test_get_supported_challenges(self):
        self.default.prepare()
        self.assertTrue(all(issubclass(sup, challenges.Challenge)
                            for sup in self.default.supported_challenges))

    def test_perform(self):
        resp_http = self.http01.response(KEY)
        resp_dns = self.dns01.response(KEY)
        self.default.prepare()
        # Check for the env vars prior to the run
        self.assertFalse("CERTBOT_VALIDATION" in os.environ.keys())
        self.assertFalse("CERTBOT_DOMAIN" in os.environ.keys())
        self.assertFalse("CERTBOT_AUTH_OUTPUT" in os.environ.keys())

        pref_resp = self.default.perform(self.achalls)
        self.assertEqual([resp_http, resp_dns], pref_resp)
        # Check for the env vars post run
        self.assertTrue("CERTBOT_VALIDATION" in os.environ.keys())
        self.assertTrue("CERTBOT_DOMAIN" in os.environ.keys())
        self.assertTrue("CERTBOT_AUTH_OUTPUT" in os.environ.keys())
        self.assertEqual(os.environ["CERTBOT_AUTH_OUTPUT"],
                         self.auth_return_value.strip())

    @mock.patch('certbot.plugins.script.Authenticator.execute')
    def test_cleanup(self, mock_exec):
        mock_exec.return_value = (0, None, None)
        self.default.prepare()
        self.default.cleanup(self.achalls)
        self.assertEqual(mock_exec.call_count, 1)

    @mock.patch('certbot.hooks.Popen')
    def test_execute(self, mock_popen):
        proc = mock.Mock()
        # tuple values: stdout, stderr, errorcode, num_of_logger_calls
        for t in [("", "", 0, 0),
                  (self.auth_return_value, "", 0, 0),
                  (None, "stderr_output", 0, 1),
                  ("whatever", "stderr_output", 1, 2),
                  (b'bytestring outval', "", 0, 0)]:
            proc = mock.Mock()
            attrs = {'communicate.return_value': (t[0], t[1]),
                     'returncode': t[2]}
            proc.configure_mock(**attrs)  # pylint: disable=star-args
            mock_popen.return_value = proc
            with mock.patch('certbot.hooks.logger.error') as mock_log:
                output = self.default.execute(self.script_exec)
                self.assertEqual(mock_log.call_count, t[3])
                self.assertTrue(isinstance(output, str))


def create_script(contents):
    """ Helper to create temporary file """
    f = tempfile.NamedTemporaryFile(delete=False, prefix='.sh')
    f.write(contents)
    f.close()
    return f.name


def create_script_exec(contents):
    """ Helper to create temporary file with exec permissions"""
    fname = create_script(contents)
    os.chmod(fname, 0o700)
    return fname
