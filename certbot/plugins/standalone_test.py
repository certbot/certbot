"""Tests for certbot.plugins.standalone."""
import socket
# https://github.com/python/typeshed/blob/master/stdlib/2and3/socket.pyi
from socket import errno as socket_errors  # type: ignore
import unittest

import josepy as jose
import mock
import six

import OpenSSL.crypto  # pylint: disable=unused-import

from acme import challenges
from acme import standalone as acme_standalone  # pylint: disable=unused-import
from acme.magic_typing import Dict, Tuple, Set  # pylint: disable=unused-import, no-name-in-module

from certbot import achallenges
from certbot import errors

from certbot.tests import acme_util
from certbot.tests import util as test_util


class ServerManagerTest(unittest.TestCase):
    """Tests for certbot.plugins.standalone.ServerManager."""

    def setUp(self):
        from certbot.plugins.standalone import ServerManager
        self.certs = {}  # type: Dict[bytes, Tuple[OpenSSL.crypto.PKey, OpenSSL.crypto.X509]]
        self.http_01_resources = {} \
        # type: Set[acme_standalone.HTTP01RequestHandler.HTTP01Resource]
        self.mgr = ServerManager(self.certs, self.http_01_resources)

    def test_init(self):
        self.assertTrue(self.mgr.certs is self.certs)
        self.assertTrue(
            self.mgr.http_01_resources is self.http_01_resources)

    def _test_run_stop(self, challenge_type):
        server = self.mgr.run(port=0, challenge_type=challenge_type)
        port = server.getsocknames()[0][1]  # pylint: disable=no-member
        self.assertEqual(self.mgr.running(), {port: server})
        self.mgr.stop(port=port)
        self.assertEqual(self.mgr.running(), {})

    def test_run_stop_http_01(self):
        self._test_run_stop(challenges.HTTP01)

    def test_run_idempotent(self):
        server = self.mgr.run(port=0, challenge_type=challenges.HTTP01)
        port = server.getsocknames()[0][1]  # pylint: disable=no-member
        server2 = self.mgr.run(port=port, challenge_type=challenges.HTTP01)
        self.assertEqual(self.mgr.running(), {port: server})
        self.assertTrue(server is server2)
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
    """Tests for certbot.plugins.standalone.Authenticator."""

    def setUp(self):
        from certbot.plugins.standalone import Authenticator

        self.config = mock.MagicMock(http01_port=get_open_port())
        self.auth = Authenticator(self.config, name="standalone")
        self.auth.servers = mock.MagicMock()

    def test_more_info(self):
        self.assertTrue(isinstance(self.auth.more_info(), six.string_types))

    def test_get_chall_pref(self):
        self.assertEqual(self.auth.get_chall_pref(domain=None),
                         [challenges.HTTP01])

    def test_perform(self):
        achalls = self._get_achalls()
        response = self.auth.perform(achalls)

        expected = [achall.response(achall.account_key) for achall in achalls]
        self.assertEqual(response, expected)

    @test_util.patch_get_utility()
    def test_perform_eaddrinuse_retry(self, mock_get_utility):
        mock_utility = mock_get_utility()
        errno = socket_errors.EADDRINUSE
        error = errors.StandaloneBindError(mock.MagicMock(errno=errno), -1)
        self.auth.servers.run.side_effect = [error] + 2 * [mock.MagicMock()]
        mock_yesno = mock_utility.yesno
        mock_yesno.return_value = True

        self.test_perform()
        self._assert_correct_yesno_call(mock_yesno)

    @test_util.patch_get_utility()
    def test_perform_eaddrinuse_no_retry(self, mock_get_utility):
        mock_utility = mock_get_utility()
        mock_yesno = mock_utility.yesno
        mock_yesno.return_value = False

        errno = socket_errors.EADDRINUSE
        self.assertRaises(errors.PluginError, self._fail_perform, errno)
        self._assert_correct_yesno_call(mock_yesno)

    def _assert_correct_yesno_call(self, mock_yesno):
        yesno_args, yesno_kwargs = mock_yesno.call_args
        self.assertTrue("in use" in yesno_args[0])
        self.assertFalse(yesno_kwargs.get("default", True))

    def test_perform_eacces(self):
        errno = socket_errors.EACCES
        self.assertRaises(errors.PluginError, self._fail_perform, errno)

    def test_perform_unexpected_socket_error(self):
        errno = socket_errors.ENOTCONN
        self.assertRaises(
            errors.StandaloneBindError, self._fail_perform, errno)

    def _fail_perform(self, errno):
        error = errors.StandaloneBindError(mock.MagicMock(errno=errno), -1)
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
            "server1": set(), "server2": set(["chall2", "chall3"])})
        self.auth.servers.stop.assert_called_once_with(1)

        self.auth.servers.running.return_value = {
            2: "server2",
        }
        self.auth.cleanup(["chall2"])
        self.assertEqual(self.auth.served, {
            "server1": set(), "server2": set(["chall3"])})
        self.assertEqual(1, self.auth.servers.stop.call_count)

        self.auth.cleanup(["chall3"])
        self.assertEqual(self.auth.served, {
            "server1": set(), "server2": set([])})
        self.auth.servers.stop.assert_called_with(2)


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
