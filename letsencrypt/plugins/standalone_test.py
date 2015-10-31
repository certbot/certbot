"""Tests for letsencrypt.plugins.standalone."""
import argparse
import socket
import unittest

import mock
import six

from acme import challenges
from acme import jose
from acme import standalone as acme_standalone

from letsencrypt import achallenges
from letsencrypt import errors
from letsencrypt import interfaces

from letsencrypt.tests import acme_util
from letsencrypt.tests import test_util


class ServerManagerTest(unittest.TestCase):
    """Tests for letsencrypt.plugins.standalone.ServerManager."""

    def setUp(self):
        from letsencrypt.plugins.standalone import ServerManager
        self.certs = {}
        self.simple_http_resources = {}
        self.mgr = ServerManager(self.certs, self.simple_http_resources)

    def test_init(self):
        self.assertTrue(self.mgr.certs is self.certs)
        self.assertTrue(
            self.mgr.simple_http_resources is self.simple_http_resources)

    def _test_run_stop(self, challenge_type):
        server = self.mgr.run(port=0, challenge_type=challenge_type)
        port = server.socket.getsockname()[1]  # pylint: disable=no-member
        self.assertEqual(self.mgr.running(), {port: server})
        self.mgr.stop(port=port)
        self.assertEqual(self.mgr.running(), {})

    def test_run_stop_dvsni(self):
        self._test_run_stop(challenges.DVSNI)

    def test_run_stop_simplehttp(self):
        self._test_run_stop(challenges.SimpleHTTP)

    def test_run_idempotent(self):
        server = self.mgr.run(port=0, challenge_type=challenges.SimpleHTTP)
        port = server.socket.getsockname()[1]  # pylint: disable=no-member
        server2 = self.mgr.run(port=port, challenge_type=challenges.SimpleHTTP)
        self.assertEqual(self.mgr.running(), {port: server})
        self.assertTrue(server is server2)
        self.mgr.stop(port)
        self.assertEqual(self.mgr.running(), {})

    def test_run_bind_error(self):
        some_server = socket.socket()
        some_server.bind(("", 0))
        port = some_server.getsockname()[1]
        self.assertRaises(
            errors.StandaloneBindError, self.mgr.run, port,
            challenge_type=challenges.SimpleHTTP)
        self.assertEqual(self.mgr.running(), {})


class SupportedChallengesValidatorTest(unittest.TestCase):
    """Tests for plugins.standalone.supported_challenges_validator."""

    def _call(self, data):
        from letsencrypt.plugins.standalone import (
            supported_challenges_validator)
        return supported_challenges_validator(data)

    def test_correct(self):
        self.assertEqual("dvsni", self._call("dvsni"))
        self.assertEqual("simpleHttp", self._call("simpleHttp"))
        self.assertEqual("dvsni,simpleHttp", self._call("dvsni,simpleHttp"))
        self.assertEqual("simpleHttp,dvsni", self._call("simpleHttp,dvsni"))

    def test_unrecognized(self):
        assert "foo" not in challenges.Challenge.TYPES
        self.assertRaises(argparse.ArgumentTypeError, self._call, "foo")

    def test_not_subset(self):
        self.assertRaises(argparse.ArgumentTypeError, self._call, "dns")


class AuthenticatorTest(unittest.TestCase):
    """Tests for letsencrypt.plugins.standalone.Authenticator."""

    def setUp(self):
        from letsencrypt.plugins.standalone import Authenticator
        self.config = mock.MagicMock(dvsni_port=1234, simple_http_port=4321,
                                     standalone_supported_challenges="dvsni,simpleHttp")
        self.auth = Authenticator(self.config, name="standalone")

    def test_supported_challenges(self):
        self.assertEqual(self.auth.supported_challenges,
                         set([challenges.DVSNI, challenges.SimpleHTTP]))

    def test_more_info(self):
        self.assertTrue(isinstance(self.auth.more_info(), six.string_types))

    def test_get_chall_pref(self):
        self.assertEqual(set(self.auth.get_chall_pref(domain=None)),
                         set([challenges.DVSNI, challenges.SimpleHTTP]))

    @mock.patch("letsencrypt.plugins.standalone.util")
    def test_perform_alredy_listening(self, mock_util):
        for chall, port in ((challenges.DVSNI.typ, 1234),
                            (challenges.SimpleHTTP.typ, 4321)):
            mock_util.already_listening.return_value = True
            self.config.standalone_supported_challenges = chall
            self.assertRaises(
                errors.MisconfigurationError, self.auth.perform, [])
            mock_util.already_listening.assert_called_once_with(port)
            mock_util.already_listening.reset_mock()

    @mock.patch("letsencrypt.plugins.standalone.zope.component.getUtility")
    def test_perform(self, unused_mock_get_utility):
        achalls = [1, 2, 3]
        self.auth.perform2 = mock.Mock(return_value=mock.sentinel.responses)
        self.assertEqual(mock.sentinel.responses, self.auth.perform(achalls))
        self.auth.perform2.assert_called_once_with(achalls)

    @mock.patch("letsencrypt.plugins.standalone.zope.component.getUtility")
    def _test_perform_bind_errors(self, errno, achalls, mock_get_utility):
        def _perform2(unused_achalls):
            raise errors.StandaloneBindError(mock.Mock(errno=errno), 1234)

        self.auth.perform2 = mock.MagicMock(side_effect=_perform2)
        self.auth.perform(achalls)
        mock_get_utility.assert_called_once_with(interfaces.IDisplay)
        notification = mock_get_utility.return_value.notification
        self.assertEqual(1, notification.call_count)
        self.assertTrue("1234" in notification.call_args[0][0])

    def test_perform_eacces(self):
        # pylint: disable=no-value-for-parameter
        self._test_perform_bind_errors(socket.errno.EACCES, [])

    def test_perform_eaddrinuse(self):
        # pylint: disable=no-value-for-parameter
        self._test_perform_bind_errors(socket.errno.EADDRINUSE, [])

    def test_perfom_unknown_bind_error(self):
        self.assertRaises(
            errors.StandaloneBindError, self._test_perform_bind_errors,
            socket.errno.ENOTCONN, [])

    def test_perform2(self):
        domain = b'localhost'
        key = jose.JWK.load(test_util.load_vector('rsa512_key.pem'))
        simple_http = achallenges.SimpleHTTP(
            challb=acme_util.SIMPLE_HTTP_P, domain=domain, account_key=key)
        dvsni = achallenges.DVSNI(
            challb=acme_util.DVSNI_P, domain=domain, account_key=key)

        self.auth.servers = mock.MagicMock()

        def _run(port, tls):  # pylint: disable=unused-argument
            return "server{0}".format(port)

        self.auth.servers.run.side_effect = _run
        responses = self.auth.perform2([simple_http, dvsni])

        self.assertTrue(isinstance(responses, list))
        self.assertEqual(2, len(responses))
        self.assertTrue(isinstance(responses[0], challenges.SimpleHTTPResponse))
        self.assertTrue(isinstance(responses[1], challenges.DVSNIResponse))

        self.assertEqual(self.auth.servers.run.mock_calls, [
            mock.call(4321, challenges.SimpleHTTP),
            mock.call(1234, challenges.DVSNI),
        ])
        self.assertEqual(self.auth.served, {
            "server1234": set([dvsni]),
            "server4321": set([simple_http]),
        })
        self.assertEqual(1, len(self.auth.simple_http_resources))
        self.assertEqual(2, len(self.auth.certs))
        self.assertEqual(list(self.auth.simple_http_resources), [
            acme_standalone.SimpleHTTPRequestHandler.SimpleHTTPResource(
                acme_util.SIMPLE_HTTP, responses[0], mock.ANY)])

    def test_cleanup(self):
        self.auth.servers = mock.Mock()
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
