#!/usr/bin/env python

"""Tests for standalone_authenticator.py."""
import mock
import unittest

import os
import pkg_resources
import signal
import socket

import OpenSSL.crypto
import OpenSSL.SSL

from letsencrypt.client import challenge_util
from letsencrypt.client import le_util


# Classes based on to allow interrupting infinite loop under test
# after one iteration, based on.
# http://igorsobreira.com/2013/03/17/testing-infinite-loops.html

class SocketAcceptOnlyNTimes(object):
    # pylint: disable=too-few-public-methods
    """
    Callable that will raise `CallableExhausted`
    exception after `limit` calls, modified to also return
    a tuple simulating the return values of a socket.accept()
    call
    """
    def __init__(self, limit):
        self.limit = limit
        self.calls = 0

    def __call__(self):
        self.calls += 1
        if self.calls > self.limit:
            raise CallableExhausted
        # Modified here for a single use as socket.accept()
        return (mock.MagicMock(), "ignored")

class CallableExhausted(Exception):
    # pylint: disable=too-few-public-methods
    """Exception raised when a method is called more than the
    specified number of times."""


class ChallPrefTest(unittest.TestCase):
    """Tests for chall_pref() method."""
    def setUp(self):
        from letsencrypt.client.standalone_authenticator import \
            StandaloneAuthenticator
        self.authenticator = StandaloneAuthenticator()

    def test_chall_pref(self):
        self.assertEqual(
            self.authenticator.get_chall_pref("example.com"), ["dvsni"])


class SNICallbackTest(unittest.TestCase):
    """Tests for sni_callback() method."""
    def setUp(self):
        from letsencrypt.client.standalone_authenticator import \
            StandaloneAuthenticator
        self.authenticator = StandaloneAuthenticator()
        name, r_b64 = "example.com", le_util.jose_b64encode("x" * 32)
        test_key = pkg_resources.resource_string(
            __name__, 'testdata/rsa256_key.pem')
        nonce, key = "abcdef", le_util.Key("foo", test_key)
        self.cert = challenge_util.dvsni_gen_cert(name, r_b64, nonce, key)[0]
        private_key = OpenSSL.crypto.load_privatekey(
            OpenSSL.crypto.FILETYPE_PEM, key.pem)
        self.authenticator.private_key = private_key
        self.authenticator.tasks = {"abcdef.acme.invalid": self.cert}
        self.authenticator.child_pid = 12345

    def test_real_servername(self):
        connection = mock.MagicMock()
        connection.get_servername.return_value = "abcdef.acme.invalid"
        self.authenticator.sni_callback(connection)
        self.assertEqual(connection.set_context.call_count, 1)
        called_ctx = connection.set_context.call_args[0][0]
        self.assertTrue(isinstance(called_ctx, OpenSSL.SSL.Context))

    def test_fake_servername(self):
        """Test behavior of SNI callback when an unexpected name is received.

        (Currently the expected behavior in this case is to return the
        "first" certificate with which the listener was configured,
        although they are stored in an unordered data structure so
        this might not be the one that was first in the challenge list
        passed to the perform method.  In the future, this might result
        in dropping the connection instead.)"""
        connection = mock.MagicMock()
        connection.get_servername.return_value = "example.com"
        self.authenticator.sni_callback(connection)
        self.assertEqual(connection.set_context.call_count, 1)
        called_ctx = connection.set_context.call_args[0][0]
        self.assertTrue(isinstance(called_ctx, OpenSSL.SSL.Context))

class ClientSignalHandlerTest(unittest.TestCase):
    """Tests for client_signal_handler() method."""
    def setUp(self):
        from letsencrypt.client.standalone_authenticator import \
            StandaloneAuthenticator
        self.authenticator = StandaloneAuthenticator()
        self.authenticator.tasks = {"foononce.acme.invalid": "stuff"}
        self.authenticator.child_pid = 12345

    def test_client_signal_handler(self):
        self.assertTrue(self.authenticator.subproc_state is None)
        self.authenticator.client_signal_handler(signal.SIGIO, None)
        self.assertEqual(self.authenticator.subproc_state, "ready")

        self.authenticator.client_signal_handler(signal.SIGUSR1, None)
        self.assertEqual(self.authenticator.subproc_state, "inuse")

        self.authenticator.client_signal_handler(signal.SIGUSR2, None)
        self.assertEqual(self.authenticator.subproc_state, "cantbind")

        # Testing the unreached path for a signal other than these
        # specified (which can't occur in normal use because this
        # function is only set as a signal handler for the above three
        # signals).
        self.assertRaises(
            ValueError, self.authenticator.client_signal_handler,
            signal.SIGPIPE, None)


class SubprocSignalHandlerTest(unittest.TestCase):
    """Tests for subproc_signal_handler() method."""
    def setUp(self):
        from letsencrypt.client.standalone_authenticator import \
            StandaloneAuthenticator
        self.authenticator = StandaloneAuthenticator()
        self.authenticator.tasks = {"foononce.acme.invalid": "stuff"}
        self.authenticator.child_pid = 12345
        self.authenticator.parent_pid = 23456

    @mock.patch("letsencrypt.client.standalone_authenticator.os.kill")
    @mock.patch("letsencrypt.client.standalone_authenticator.sys.exit")
    def test_subproc_signal_handler(self, mock_exit, mock_kill):
        self.authenticator.ssl_conn = mock.MagicMock()
        self.authenticator.connection = mock.MagicMock()
        self.authenticator.sock = mock.MagicMock()
        self.authenticator.subproc_signal_handler(signal.SIGINT, None)
        self.assertEquals(self.authenticator.ssl_conn.shutdown.call_count, 1)
        self.assertEquals(self.authenticator.ssl_conn.close.call_count, 1)
        self.assertEquals(self.authenticator.connection.close.call_count, 1)
        self.assertEquals(self.authenticator.sock.close.call_count, 1)
        mock_kill.assert_called_once_with(
            self.authenticator.parent_pid, signal.SIGUSR1)
        mock_exit.assert_called_once_with(0)

    @mock.patch("letsencrypt.client.standalone_authenticator.os.kill")
    @mock.patch("letsencrypt.client.standalone_authenticator.sys.exit")
    def test_subproc_signal_handler_trouble(self, mock_exit, mock_kill):
        """Test attempting to shut down a non-existent connection.

        (This could occur because none was established or active at the
        time the signal handler tried to perform the cleanup)."""
        self.authenticator.ssl_conn = mock.MagicMock()
        self.authenticator.connection = mock.MagicMock()
        self.authenticator.sock = mock.MagicMock()
        # AttributeError simulates the case where one of these properties
        # is None because no connection exists.  We raise it for
        # ssl_conn.close() instead of ssl_conn.shutdown() for better code
        # coverage.
        self.authenticator.ssl_conn.close.side_effect = AttributeError("!")
        self.authenticator.connection.close.side_effect = AttributeError("!")
        self.authenticator.sock.close.side_effect = AttributeError("!")
        self.authenticator.subproc_signal_handler(signal.SIGINT, None)
        self.assertEquals(self.authenticator.ssl_conn.shutdown.call_count, 1)
        self.assertEquals(self.authenticator.ssl_conn.close.call_count, 1)
        self.assertEquals(self.authenticator.connection.close.call_count, 1)
        self.assertEquals(self.authenticator.sock.close.call_count, 1)
        mock_kill.assert_called_once_with(
            self.authenticator.parent_pid, signal.SIGUSR1)
        mock_exit.assert_called_once_with(0)


class PerformTest(unittest.TestCase):
    """Tests for perform() method."""
    def setUp(self):
        from letsencrypt.client.standalone_authenticator import \
            StandaloneAuthenticator
        self.authenticator = StandaloneAuthenticator()

    def test_can_perform(self):
        """What happens if start_listener() returns True."""
        test_key = pkg_resources.resource_string(
            __name__, 'testdata/rsa256_key.pem')
        key = le_util.Key("something", test_key)
        chall1 = challenge_util.DvsniChall(
            "foo.example.com", "whee", "foononce", key)
        chall2 = challenge_util.DvsniChall(
            "bar.example.com", "whee", "barnonce", key)
        bad_chall = ("This", "Represents", "A Non-DVSNI", "Challenge")
        self.authenticator.start_listener = mock.Mock()
        self.authenticator.start_listener.return_value = True
        result = self.authenticator.perform([chall1, chall2, bad_chall])
        self.assertEqual(len(self.authenticator.tasks), 2)
        self.assertTrue(
            self.authenticator.tasks.has_key("foononce.acme.invalid"))
        self.assertTrue(
            self.authenticator.tasks.has_key("barnonce.acme.invalid"))
        self.assertTrue(isinstance(result, list))
        self.assertEqual(len(result), 3)
        self.assertTrue(isinstance(result[0], dict))
        self.assertTrue(isinstance(result[1], dict))
        self.assertFalse(result[2])
        self.assertTrue(result[0].has_key("s"))
        self.assertTrue(result[1].has_key("s"))
        self.authenticator.start_listener.assert_called_once_with(443, key)

    def test_cannot_perform(self):
        """What happens if start_listener() returns False."""
        test_key = pkg_resources.resource_string(
            __name__, 'testdata/rsa256_key.pem')
        key = le_util.Key("something", test_key)
        chall1 = challenge_util.DvsniChall(
            "foo.example.com", "whee", "foononce", key)
        chall2 = challenge_util.DvsniChall(
            "bar.example.com", "whee", "barnonce", key)
        bad_chall = ("This", "Represents", "A Non-DVSNI", "Challenge")
        self.authenticator.start_listener = mock.Mock()
        self.authenticator.start_listener.return_value = False
        result = self.authenticator.perform([chall1, chall2, bad_chall])
        self.assertEqual(len(self.authenticator.tasks), 2)
        self.assertTrue(
            self.authenticator.tasks.has_key("foononce.acme.invalid"))
        self.assertTrue(
            self.authenticator.tasks.has_key("barnonce.acme.invalid"))
        self.assertTrue(isinstance(result, list))
        self.assertEqual(len(result), 3)
        self.assertEqual(result, [None, None, False])
        self.authenticator.start_listener.assert_called_once_with(443, key)

    def test_perform_with_pending_tasks(self):
        self.authenticator.tasks = {"foononce.acme.invalid": "cert_data"}
        extra_challenge = challenge_util.DvsniChall("a", "b", "c", "d")
        self.assertRaises(
            Exception, self.authenticator.perform, [extra_challenge])

    def test_perform_without_challenge_list(self):
        extra_challenge = challenge_util.DvsniChall("a", "b", "c", "d")
        # This is wrong because a challenge must be specified.
        self.assertRaises(Exception, self.authenticator.perform, [])
        # This is wrong because it must be a list, not a bare challenge.
        self.assertRaises(
            Exception, self.authenticator.perform, extra_challenge)
        # This is wrong because the list must contain at least one challenge.
        self.assertRaises(
            Exception, self.authenticator.perform, range(20))


class StartListenerTest(unittest.TestCase):
    """Tests for start_listener() method."""
    def setUp(self):
        from letsencrypt.client.standalone_authenticator import \
            StandaloneAuthenticator
        self.authenticator = StandaloneAuthenticator()

    @mock.patch("letsencrypt.client.standalone_authenticator."
                "Crypto.Random.atfork")
    @mock.patch("letsencrypt.client.standalone_authenticator.os.fork")
    def test_start_listener_fork_parent(self, mock_fork, mock_atfork):
        self.authenticator.do_parent_process = mock.Mock()
        self.authenticator.do_parent_process.return_value = True
        mock_fork.return_value = 22222
        result = self.authenticator.start_listener(1717, "key")
        # start_listener is expected to return the True or False return
        # value from do_parent_process.
        self.assertTrue(result)
        self.assertEqual(self.authenticator.child_pid, 22222)
        self.authenticator.do_parent_process.assert_called_once_with(1717)
        mock_atfork.assert_called_once_with()

    @mock.patch("letsencrypt.client.standalone_authenticator."
                "Crypto.Random.atfork")
    @mock.patch("letsencrypt.client.standalone_authenticator.os.fork")
    def test_start_listener_fork_child(self, mock_fork, mock_atfork):
        self.authenticator.do_parent_process = mock.Mock()
        self.authenticator.do_child_process = mock.Mock()
        mock_fork.return_value = 0
        self.authenticator.start_listener(1717, "key")
        self.assertEqual(self.authenticator.child_pid, os.getpid())
        self.authenticator.do_child_process.assert_called_once_with(
            1717, "key")
        mock_atfork.assert_called_once_with()

class DoParentProcessTest(unittest.TestCase):
    """Tests for do_parent_process() method."""
    def setUp(self):
        from letsencrypt.client.standalone_authenticator import \
            StandaloneAuthenticator
        self.authenticator = StandaloneAuthenticator()

    @mock.patch("letsencrypt.client.standalone_authenticator.signal.signal")
    @mock.patch("letsencrypt.client.standalone_authenticator."
                "zope.component.getUtility")
    def test_do_parent_process_ok(self, mock_get_utility, mock_signal):
        self.authenticator.subproc_state = "ready"
        result = self.authenticator.do_parent_process(1717)
        self.assertTrue(result)
        self.assertEqual(mock_get_utility.call_count, 1)
        self.assertEqual(mock_signal.call_count, 3)

    @mock.patch("letsencrypt.client.standalone_authenticator.signal.signal")
    @mock.patch("letsencrypt.client.standalone_authenticator."
                "zope.component.getUtility")
    def test_do_parent_process_inuse(self, mock_get_utility, mock_signal):
        self.authenticator.subproc_state = "inuse"
        result = self.authenticator.do_parent_process(1717)
        self.assertFalse(result)
        self.assertEqual(mock_get_utility.call_count, 1)
        self.assertEqual(mock_signal.call_count, 3)

    @mock.patch("letsencrypt.client.standalone_authenticator.signal.signal")
    @mock.patch("letsencrypt.client.standalone_authenticator."
                "zope.component.getUtility")
    def test_do_parent_process_cantbind(self, mock_get_utility, mock_signal):
        self.authenticator.subproc_state = "cantbind"
        result = self.authenticator.do_parent_process(1717)
        self.assertFalse(result)
        self.assertEqual(mock_get_utility.call_count, 1)
        self.assertEqual(mock_signal.call_count, 3)

    @mock.patch("letsencrypt.client.standalone_authenticator.signal.signal")
    @mock.patch("letsencrypt.client.standalone_authenticator."
                "zope.component.getUtility")
    def test_do_parent_process_timeout(self, mock_get_utility, mock_signal):
        # Normally times out in 5 seconds and returns False.  We can
        # now set delay_amount to a lower value so that it times out
        # faster than it would under normal use.
        result = self.authenticator.do_parent_process(1717, delay_amount=1)
        self.assertFalse(result)
        self.assertEqual(mock_get_utility.call_count, 1)
        self.assertEqual(mock_signal.call_count, 3)


class DoChildProcessTest(unittest.TestCase):
    """Tests for do_child_process() method."""
    def setUp(self):
        from letsencrypt.client.standalone_authenticator import \
            StandaloneAuthenticator
        self.authenticator = StandaloneAuthenticator()
        name, r_b64 = "example.com", le_util.jose_b64encode("x" * 32)
        test_key = pkg_resources.resource_string(
            __name__, 'testdata/rsa256_key.pem')
        nonce, key = "abcdef", le_util.Key("foo", test_key)
        self.key = key
        self.cert = challenge_util.dvsni_gen_cert(name, r_b64, nonce, key)[0]
        private_key = OpenSSL.crypto.load_privatekey(
            OpenSSL.crypto.FILETYPE_PEM, key.pem)
        self.authenticator.private_key = private_key
        self.authenticator.tasks = {"abcdef.acme.invalid": self.cert}
        self.authenticator.parent_pid = 12345

    @mock.patch("letsencrypt.client.standalone_authenticator.socket.socket")
    @mock.patch("letsencrypt.client.standalone_authenticator.os.kill")
    @mock.patch("letsencrypt.client.standalone_authenticator.sys.exit")
    def test_do_child_process_cantbind1(
            self, mock_exit, mock_kill, mock_socket):
        mock_exit.side_effect = IndentationError("subprocess would exit here")
        eaccess = socket.error(socket.errno.EACCES, "Permission denied")
        sample_socket = mock.MagicMock()
        sample_socket.bind.side_effect = eaccess
        mock_socket.return_value = sample_socket
        # Using the IndentationError as an error that cannot easily be
        # generated at runtime, to indicate the behavior of sys.exit has
        # taken effect without actually causing the test process to exit.
        # (Just replacing it with a no-op causes logic errors because the
        # do_child_process code assumes that calling sys.exit() will
        # cause subsequent code not to be executed.)
        self.assertRaises(
            IndentationError, self.authenticator.do_child_process, 1717,
            self.key)
        mock_exit.assert_called_once_with(1)
        mock_kill.assert_called_once_with(12345, signal.SIGUSR2)

    @mock.patch("letsencrypt.client.standalone_authenticator.socket.socket")
    @mock.patch("letsencrypt.client.standalone_authenticator.os.kill")
    @mock.patch("letsencrypt.client.standalone_authenticator.sys.exit")
    def test_do_child_process_cantbind2(self, mock_exit, mock_kill,
                                        mock_socket):
        mock_exit.side_effect = IndentationError("subprocess would exit here")
        eaccess = socket.error(socket.errno.EADDRINUSE, "Port already in use")
        sample_socket = mock.MagicMock()
        sample_socket.bind.side_effect = eaccess
        mock_socket.return_value = sample_socket
        self.assertRaises(
            IndentationError, self.authenticator.do_child_process, 1717,
            self.key)
        mock_exit.assert_called_once_with(1)
        mock_kill.assert_called_once_with(12345, signal.SIGUSR1)

    @mock.patch("letsencrypt.client.standalone_authenticator.socket.socket")
    def test_do_child_process_cantbind3(self, mock_socket):
        """Test case where attempt to bind socket results in an unhandled
        socket error.  (The expected behavior is arguably wrong because it
        will crash the program; the reason for the expected behavior is
        that we don't have a way to report arbitrary socket errors.)"""
        eio = socket.error(socket.errno.EIO, "Imaginary unhandled error")
        sample_socket = mock.MagicMock()
        sample_socket.bind.side_effect = eio
        mock_socket.return_value = sample_socket
        self.assertRaises(
            socket.error, self.authenticator.do_child_process, 1717, self.key)

    @mock.patch("letsencrypt.client.standalone_authenticator."
                "OpenSSL.SSL.Connection")
    @mock.patch("letsencrypt.client.standalone_authenticator.socket.socket")
    @mock.patch("letsencrypt.client.standalone_authenticator.os.kill")
    def test_do_child_process_success(self, mock_kill, mock_socket,
                                      mock_connection):
        sample_socket = mock.MagicMock()
        sample_socket.accept.side_effect = SocketAcceptOnlyNTimes(2)
        mock_socket.return_value = sample_socket
        mock_connection.return_value = mock.MagicMock()
        self.assertRaises(
            CallableExhausted, self.authenticator.do_child_process, 1717,
            self.key)
        mock_socket.assert_called_once_with()
        sample_socket.bind.assert_called_once_with(("0.0.0.0", 1717))
        sample_socket.listen.assert_called_once_with(1)
        self.assertEqual(sample_socket.accept.call_count, 3)
        mock_kill.assert_called_once_with(12345, signal.SIGIO)
        # TODO: We could have some tests about the fact that the listener
        #       asks OpenSSL to negotiate a TLS connection (and correctly
        #       sets the SNI callback function).


class CleanupTest(unittest.TestCase):
    """Tests for cleanup() method."""
    def setUp(self):
        from letsencrypt.client.standalone_authenticator import \
            StandaloneAuthenticator
        self.authenticator = StandaloneAuthenticator()
        self.authenticator.tasks = {"foononce.acme.invalid": "stuff"}
        self.authenticator.child_pid = 12345

    @mock.patch("letsencrypt.client.standalone_authenticator.os.kill")
    @mock.patch("letsencrypt.client.standalone_authenticator.time.sleep")
    def test_cleanup(self, mock_sleep, mock_kill):
        mock_sleep.return_value = None
        mock_kill.return_value = None
        chall = challenge_util.DvsniChall(
            "foo.example.com", "whee", "foononce", "key")
        self.authenticator.cleanup([chall])
        mock_kill.assert_called_once_with(12345, signal.SIGINT)
        mock_sleep.assert_called_once_with(1)

    def test_bad_cleanup(self):
        chall = challenge_util.DvsniChall(
            "bad.example.com", "whee", "badnonce", "key")
        self.assertRaises(ValueError, self.authenticator.cleanup, [chall])


if __name__ == '__main__':
    unittest.main()
