"""Tests for certbot.plugins.manual."""
import signal
import unittest

import mock

from acme import challenges
from acme import errors as acme_errors
from acme import jose

from certbot import achallenges
from certbot import errors

from certbot.tests import acme_util
from certbot.tests import test_util


KEY = jose.JWKRSA.load(test_util.load_vector("rsa512_key.pem"))


class AuthenticatorTest(unittest.TestCase):
    """Tests for certbot.plugins.manual.Authenticator."""

    def setUp(self):
        from certbot.plugins.manual import Authenticator
        self.config = mock.MagicMock(
            http01_port=8080, manual_test_mode=False,
            manual_public_ip_logging_ok=False, noninteractive_mode=True)
        self.auth = Authenticator(config=self.config, name="manual")

        self.http01 = achallenges.KeyAuthorizationAnnotatedChallenge(
            challb=acme_util.HTTP01_P, domain="foo.com", account_key=KEY)
        self.dns01 = achallenges.KeyAuthorizationAnnotatedChallenge(
            challb=acme_util.DNS01_P, domain="foo.com", account_key=KEY)

        self.achalls = [self.http01, self.dns01]

        config_test_mode = mock.MagicMock(
            http01_port=8080, manual_test_mode=True, noninteractive_mode=True)
        self.auth_test_mode = Authenticator(
            config=config_test_mode, name="manual")

    def test_prepare(self):
        self.assertRaises(errors.PluginError, self.auth.prepare)
        self.auth_test_mode.prepare()  # error not raised

    def test_more_info(self):
        self.assertTrue(isinstance(self.auth.more_info(), str))

    def test_get_chall_pref(self):
        self.assertTrue(all(issubclass(pref, challenges.Challenge)
                            for pref in self.auth.get_chall_pref("foo.com")))

    @mock.patch("certbot.plugins.manual.zope.component.getUtility")
    def test_perform_empty(self, mock_interaction):
        mock_interaction().yesno.return_value = True
        self.assertEqual([], self.auth.perform([]))

    @mock.patch("certbot.plugins.manual.zope.component.getUtility")
    @mock.patch("certbot.plugins.manual.sys.stdout")
    @mock.patch("acme.challenges.HTTP01Response.simple_verify")
    @mock.patch("six.moves.input")
    def test_perform(self, mock_raw_input, mock_verify, mock_stdout, mock_interaction):
        mock_verify.return_value = True
        mock_interaction().yesno.return_value = True

        resp_http = self.http01.response(KEY)
        resp_dns = self.dns01.response(KEY)

        self.assertEqual([resp_http, resp_dns], self.auth.perform(self.achalls))
        self.assertEqual(2, mock_raw_input.call_count)
        mock_verify.assert_called_with(
            self.http01.challb.chall, "foo.com", KEY.public_key(), 8080)

        message = mock_stdout.write.mock_calls[0][1][0]
        self.assertTrue(self.http01.chall.encode("token") in message)

        mock_verify.return_value = False
        with mock.patch("certbot.plugins.manual.logger") as mock_logger:
            self.auth.perform(self.achalls)
            self.assertEqual(2, mock_logger.warning.call_count)

    @mock.patch("certbot.plugins.manual.zope.component.getUtility")
    @mock.patch("acme.challenges.DNS01Response.simple_verify")
    @mock.patch("six.moves.input")
    def test_perform_missing_dependency(self, mock_raw_input, mock_verify, mock_interaction):
        mock_interaction().yesno.return_value = True
        mock_verify.side_effect = acme_errors.DependencyError()

        with mock.patch("certbot.plugins.manual.logger") as mock_logger:
            self.auth.perform([self.dns01])
            self.assertEqual(1, mock_logger.warning.call_count)

        mock_raw_input.assert_called_once_with("Press ENTER to continue")

    @mock.patch("certbot.plugins.manual.zope.component.getUtility")
    @mock.patch("certbot.plugins.manual.Authenticator._notify_and_wait")
    def test_disagree_with_ip_logging(self, mock_notify, mock_interaction):
        mock_interaction().yesno.return_value = False
        mock_notify.side_effect = errors.Error("Exception not raised, \
            continued execution even after disagreeing with IP logging")

        self.assertRaises(errors.PluginError, self.auth.perform, self.achalls)

    @mock.patch("certbot.plugins.manual.subprocess.Popen", autospec=True)
    def test_perform_test_command_oserror(self, mock_popen):
        mock_popen.side_effect = OSError
        self.assertEqual([False], self.auth_test_mode.perform([self.http01]))

    @mock.patch("certbot.plugins.manual.socket.socket")
    @mock.patch("certbot.plugins.manual.time.sleep", autospec=True)
    @mock.patch("certbot.plugins.manual.subprocess.Popen", autospec=True)
    def test_perform_test_command_run_failure(
            self, mock_popen, unused_mock_sleep, unused_mock_socket):
        mock_popen.poll.return_value = 10
        mock_popen.return_value.pid = 1234
        self.assertRaises(
            errors.Error, self.auth_test_mode.perform, self.achalls)

    def test_cleanup_test_mode_already_terminated(self):
        # pylint: disable=protected-access
        self.auth_test_mode._httpd = httpd = mock.Mock()
        httpd.poll.return_value = 0
        self.auth_test_mode.cleanup(self.achalls)

    @mock.patch("certbot.plugins.manual.os.killpg", autospec=True)
    def test_cleanup_test_mode_kills_still_running(self, mock_killpg):
        # pylint: disable=protected-access
        self.auth_test_mode._httpd = httpd = mock.Mock(pid=1234)
        httpd.poll.return_value = None
        self.auth_test_mode.cleanup(self.achalls)
        mock_killpg.assert_called_once_with(1234, signal.SIGTERM)


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
