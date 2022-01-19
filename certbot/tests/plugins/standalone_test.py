"""Tests for certbot._internal.plugins.standalone."""
import errno
import socket
from typing import Dict
from typing import Set
from typing import Tuple
import unittest

import josepy as jose
import OpenSSL.crypto

from acme import challenges
from acme import standalone as acme_standalone
from certbot import achallenges
from certbot import errors
from certbot.tests import acme_util
from certbot.tests import util as test_util

try:
    import mock
except ImportError: # pragma: no cover
    from unittest import mock


class ServerManagerTest(unittest.TestCase):
    """Tests for certbot._internal.plugins.standalone.ServerManager."""

    def setUp(self):
        from certbot._internal.plugins.standalone import ServerManager
        self.certs: Dict[bytes, Tuple[OpenSSL.crypto.PKey, OpenSSL.crypto.X509]] = {}
        self.http_01_resources: Set[acme_standalone.HTTP01RequestHandler.HTTP01Resource] = {}
        self.mgr = ServerManager(self.certs, self.http_01_resources)

    def test_init(self):
        self.assertIs(self.mgr.certs, self.certs)
        self.assertIs(self.mgr.http_01_resources, self.http_01_resources)

    def _test_run_stop(self, challenge_type):
        server = self.mgr.run(port=0, challenge_type=challenge_type)
        port = server.getsocknames()[0][1]
        self.assertEqual(self.mgr.running(), {port: server})
        self.mgr.stop(port=port)
        self.assertEqual(self.mgr.running(), {})

    def test_run_stop_http_01(self):
        self._test_run_stop(challenges.HTTP01)

    def test_run_idempotent(self):
        server = self.mgr.run(port=0, challenge_type=challenges.HTTP01)
        port = server.getsocknames()[0][1]
        server2 = self.mgr.run(port=port, challenge_type=challenges.HTTP01)
        self.assertEqual(self.mgr.running(), {port: server})
        self.assertIs(server, server2)
        self.mgr.stop(port)
        self.assertEqual(self.mgr.running(), {})

    def test_run_bind_error(self):
        some_server = socket.socket(socket.AF_INET6)
        some_server.bind(("", 0))
        port = some_server.getsockname()[1]
        maybe_another_server = socket.socket()
        try:
            maybe_another_server.bind(("", port))
        except socket.error:
            pass
        self.assertRaises(
            errors.StandaloneBindError, self.mgr.run, port,
            challenge_type=challenges.HTTP01)
        self.assertEqual(self.mgr.running(), {})
        some_server.close()
        maybe_another_server.close()


def get_open_port():
    """Gets an open port number from the OS."""
    open_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    open_socket.bind(("", 0))
    port = open_socket.getsockname()[1]
    open_socket.close()
    return port


class AuthenticatorTest(unittest.TestCase):
    """Tests for certbot._internal.plugins.standalone.Authenticator."""

    def setUp(self):
        from certbot._internal.plugins.standalone import Authenticator

        self.config = mock.MagicMock(http01_port=get_open_port())
        self.auth = Authenticator(self.config, name="standalone")
        self.auth.servers = mock.MagicMock()

    def test_more_info(self):
        self.assertIsInstance(self.auth.more_info(), str)

    def test_get_chall_pref(self):
        self.assertEqual(self.auth.get_chall_pref(domain=None),
                         [challenges.HTTP01])

    def test_perform(self):
        achalls = self._get_achalls()
        response = self.auth.perform(achalls)

        expected = [achall.response(achall.account_key) for achall in achalls]
        self.assertEqual(response, expected)

    @test_util.patch_display_util()
    def test_perform_eaddrinuse_retry(self, mock_get_utility):
        mock_utility = mock_get_utility()
        encountered_errno = errno.EADDRINUSE
        error = errors.StandaloneBindError(mock.MagicMock(errno=encountered_errno), -1)
        self.auth.servers.run.side_effect = [error] + 2 * [mock.MagicMock()]
        mock_yesno = mock_utility.yesno
        mock_yesno.return_value = True

        self.test_perform()
        self._assert_correct_yesno_call(mock_yesno)

    @test_util.patch_display_util()
    def test_perform_eaddrinuse_no_retry(self, mock_get_utility):
        mock_utility = mock_get_utility()
        mock_yesno = mock_utility.yesno
        mock_yesno.return_value = False

        encountered_errno = errno.EADDRINUSE
        self.assertRaises(errors.PluginError, self._fail_perform, encountered_errno)
        self._assert_correct_yesno_call(mock_yesno)

    def _assert_correct_yesno_call(self, mock_yesno):
        yesno_args, yesno_kwargs = mock_yesno.call_args
        self.assertIn("in use", yesno_args[0])
        self.assertFalse(yesno_kwargs.get("default", True))

    def test_perform_eacces(self):
        encountered_errno = errno.EACCES
        self.assertRaises(errors.PluginError, self._fail_perform, encountered_errno)

    def test_perform_unexpected_socket_error(self):
        encountered_errno = errno.ENOTCONN
        self.assertRaises(
            errors.StandaloneBindError, self._fail_perform, encountered_errno)

    def _fail_perform(self, encountered_errno):
        error = errors.StandaloneBindError(mock.MagicMock(errno=encountered_errno), -1)
        self.auth.servers.run.side_effect = error
        self.auth.perform(self._get_achalls())

    @classmethod
    def _get_achalls(cls):
        domain = b'localhost'
        key = jose.JWK.load(test_util.load_vector('rsa512_key.pem'))
        http_01 = achallenges.KeyAuthorizationAnnotatedChallenge(
            challb=acme_util.HTTP01_P, domain=domain, account_key=key)

        return [http_01]

    def test_cleanup(self):
        self.auth.servers.running.return_value = {
            1: "server1",
            2: "server2",
        }
        self.auth.served["server1"].add("chall1")
        self.auth.served["server2"].update(["chall2", "chall3"])

        self.auth.cleanup(["chall1"])
        self.assertEqual(self.auth.served, {
            "server1": set(), "server2": {"chall2", "chall3"}})
        self.auth.servers.stop.assert_called_once_with(1)

        self.auth.servers.running.return_value = {
            2: "server2",
        }
        self.auth.cleanup(["chall2"])
        self.assertEqual(self.auth.served, {
            "server1": set(), "server2": {"chall3"}})
        self.assertEqual(1, self.auth.servers.stop.call_count)

        self.auth.cleanup(["chall3"])
        self.assertEqual(self.auth.served, {
            "server1": set(), "server2": set()})
        self.auth.servers.stop.assert_called_with(2)

    def test_auth_hint(self):
        self.config.http01_port = "80"
        self.config.http01_address = None
        self.assertIn("on port 80", self.auth.auth_hint([]))
        self.config.http01_address = "127.0.0.1"
        self.assertIn("on 127.0.0.1:80", self.auth.auth_hint([]))


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
