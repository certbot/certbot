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


class AuthenticatorTest(unittest.TestCase):
    """Tests for letsencrypt.plugins.manual.Authenticator."""

    def setUp(self):
        from letsencrypt.plugins.manual import Authenticator
        self.config = mock.MagicMock(
            http01_port=8080, manual_test_mode=False)
        self.auth = Authenticator(config=self.config, name="manual")
        self.achalls = [achallenges.KeyAuthorizationAnnotatedChallenge(
            challb=acme_util.HTTP01_P, domain="foo.com", account_key=KEY)]

        config_test_mode = mock.MagicMock(
            http01_port=8080, manual_test_mode=True)
        self.auth_test_mode = Authenticator(
            config=config_test_mode, name="manual")

    def test_more_info(self):
        self.assertTrue(isinstance(self.auth.more_info(), str))

    def test_get_chall_pref(self):
        self.assertTrue(all(issubclass(pref, challenges.Challenge)
                            for pref in self.auth.get_chall_pref("foo.com")))

    def test_perform_empty(self):
        self.assertEqual([], self.auth.perform([]))

    @mock.patch("letsencrypt.plugins.manual.zope.component.getUtility")
    @mock.patch("letsencrypt.plugins.manual.sys.stdout")
    @mock.patch("acme.challenges.HTTP01Response.simple_verify")
    @mock.patch("__builtin__.raw_input")
    def test_perform(self, mock_raw_input, mock_verify, mock_stdout, mock_interaction):
        mock_verify.return_value = True
        mock_interaction().yesno.return_value = True

        resp = self.achalls[0].response(KEY)
        self.assertEqual([resp], self.auth.perform(self.achalls))
        self.assertEqual(1, mock_raw_input.call_count)
        mock_verify.assert_called_with(
            self.achalls[0].challb.chall, "foo.com", KEY.public_key(), 8080)

        message = mock_stdout.write.mock_calls[0][1][0]
        self.assertTrue(self.achalls[0].chall.encode("token") in message)

        mock_verify.return_value = False
        self.assertEqual([None], self.auth.perform(self.achalls))

    @mock.patch("letsencrypt.plugins.manual.zope.component.getUtility")
    @mock.patch("letsencrypt.plugins.manual.Authenticator._notify_and_wait")
    def test_disagree_with_ip_logging(self, mock_notify, mock_interaction):
        mock_interaction().yesno.return_value = False
        mock_notify.side_effect = errors.Error("Exception not raised, \
            continued execution even after disagreeing with IP logging")

        self.assertRaises(errors.PluginError, self.auth.perform, self.achalls)

    @mock.patch("letsencrypt.plugins.manual.subprocess.Popen", autospec=True)
    def test_perform_test_command_oserror(self, mock_popen):
        mock_popen.side_effect = OSError
        self.assertEqual([False], self.auth_test_mode.perform(self.achalls))

    @mock.patch("letsencrypt.plugins.manual.socket.socket")
    @mock.patch("letsencrypt.plugins.manual.time.sleep", autospec=True)
    @mock.patch("letsencrypt.plugins.manual.subprocess.Popen", autospec=True)
    def test_perform_test_command_run_failure(
            self, mock_popen, unused_mock_sleep, unused_mock_socket):
        mock_popen.poll.return_value = 10
        mock_popen.return_value.pid = 1234
        self.assertRaises(
            errors.Error, self.auth_test_mode.perform, self.achalls)

    @mock.patch("letsencrypt.plugins.manual.socket.socket")
    @mock.patch("letsencrypt.plugins.manual.time.sleep", autospec=True)
    @mock.patch("acme.challenges.HTTP01Response.simple_verify",
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


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
