"""Tests for letsencrypt.plugins.standalone.authenticator."""
import os
import psutil
import signal
import socket
import unittest

import mock
import OpenSSL

from acme import challenges
from acme import jose

from letsencrypt import achallenges

from letsencrypt.tests import acme_util
from letsencrypt.tests import test_util


ACCOUNT_KEY = jose.JWKRSA.load(test_util.load_vector("rsa512_key.pem"))
CHALL_KEY_PEM = test_util.load_vector("rsa512_key_2.pem")
CHALL_KEY = OpenSSL.crypto.load_privatekey(
    OpenSSL.crypto.FILETYPE_PEM, CHALL_KEY_PEM)
CONFIG = mock.Mock(dvsni_port=5001)


# Classes based on to allow interrupting infinite loop under test
# after one iteration, based on.
# http://igorsobreira.com/2013/03/17/testing-infinite-loops.html

class _SocketAcceptOnlyNTimes(object):
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
        from letsencrypt.plugins.standalone.authenticator import \
            StandaloneAuthenticator
        self.authenticator = StandaloneAuthenticator(config=CONFIG, name=None)

    def test_chall_pref(self):
        self.assertEqual(self.authenticator.get_chall_pref("example.com"),
                         [challenges.DVSNI])


class SNICallbackTest(unittest.TestCase):
    """Tests for sni_callback() method."""
    def setUp(self):
        from letsencrypt.plugins.standalone.authenticator import \
            StandaloneAuthenticator
        self.authenticator = StandaloneAuthenticator(config=CONFIG, name=None)
        self.cert = achallenges.DVSNI(
            challb=acme_util.DVSNI_P,
            domain="example.com",
            account_key=ACCOUNT_KEY
        ).gen_cert_and_response(key_pem=CHALL_KEY_PEM)[1]
        self.authenticator.private_key = CHALL_KEY
        self.authenticator.sni_names = {"abcdef.acme.invalid": self.cert}
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
        from letsencrypt.plugins.standalone.authenticator import \
            StandaloneAuthenticator
        self.authenticator = StandaloneAuthenticator(config=CONFIG, name=None)
        self.authenticator.tasks = {"footoken.acme.invalid": "stuff"}
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
        from letsencrypt.plugins.standalone.authenticator import \
            StandaloneAuthenticator
        self.authenticator = StandaloneAuthenticator(config=CONFIG, name=None)
        self.authenticator.tasks = {"footoken.acme.invalid": "stuff"}
        self.authenticator.child_pid = 12345
        self.authenticator.parent_pid = 23456

    @mock.patch("letsencrypt.plugins.standalone.authenticator.os.kill")
    @mock.patch("letsencrypt.plugins.standalone.authenticator.sys.exit")
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

    @mock.patch("letsencrypt.plugins.standalone.authenticator.os.kill")
    @mock.patch("letsencrypt.plugins.standalone.authenticator.sys.exit")
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


class AlreadyListeningTest(unittest.TestCase):
    """Tests for already_listening() method."""
    def setUp(self):
        from letsencrypt.plugins.standalone.authenticator import \
            StandaloneAuthenticator
        self.authenticator = StandaloneAuthenticator(config=CONFIG, name=None)

    @mock.patch("letsencrypt.plugins.standalone.authenticator.psutil."
                "net_connections")
    @mock.patch("letsencrypt.plugins.standalone.authenticator.psutil.Process")
    @mock.patch("letsencrypt.plugins.standalone.authenticator."
                "zope.component.getUtility")
    def test_race_condition(self, mock_get_utility, mock_process, mock_net):
        # This tests a race condition, or permission problem, or OS
        # incompatibility in which, for some reason, no process name can be
        # found to match the identified listening PID.
        from psutil._common import sconn
        conns = [
            sconn(fd=-1, family=2, type=1, laddr=("0.0.0.0", 30),
                  raddr=(), status="LISTEN", pid=None),
            sconn(fd=3, family=2, type=1, laddr=("192.168.5.10", 32783),
                  raddr=("20.40.60.80", 22), status="ESTABLISHED", pid=1234),
            sconn(fd=-1, family=10, type=1, laddr=("::1", 54321),
                  raddr=("::1", 111), status="CLOSE_WAIT", pid=None),
            sconn(fd=3, family=2, type=1, laddr=("0.0.0.0", 17),
                  raddr=(), status="LISTEN", pid=4416)]
        mock_net.return_value = conns
        mock_process.side_effect = psutil.NoSuchProcess("No such PID")
        # We simulate being unable to find the process name of PID 4416,
        # which results in returning False.
        self.assertFalse(self.authenticator.already_listening(17))
        self.assertEqual(mock_get_utility.generic_notification.call_count, 0)
        mock_process.assert_called_once_with(4416)

    @mock.patch("letsencrypt.plugins.standalone.authenticator.psutil."
                "net_connections")
    @mock.patch("letsencrypt.plugins.standalone.authenticator.psutil.Process")
    @mock.patch("letsencrypt.plugins.standalone.authenticator."
                "zope.component.getUtility")
    def test_not_listening(self, mock_get_utility, mock_process, mock_net):
        from psutil._common import sconn
        conns = [
            sconn(fd=-1, family=2, type=1, laddr=("0.0.0.0", 30),
                  raddr=(), status="LISTEN", pid=None),
            sconn(fd=3, family=2, type=1, laddr=("192.168.5.10", 32783),
                  raddr=("20.40.60.80", 22), status="ESTABLISHED", pid=1234),
            sconn(fd=-1, family=10, type=1, laddr=("::1", 54321),
                  raddr=("::1", 111), status="CLOSE_WAIT", pid=None)]
        mock_net.return_value = conns
        mock_process.name.return_value = "inetd"
        self.assertFalse(self.authenticator.already_listening(17))
        self.assertEqual(mock_get_utility.generic_notification.call_count, 0)
        self.assertEqual(mock_process.call_count, 0)

    @mock.patch("letsencrypt.plugins.standalone.authenticator.psutil."
                "net_connections")
    @mock.patch("letsencrypt.plugins.standalone.authenticator.psutil.Process")
    @mock.patch("letsencrypt.plugins.standalone.authenticator."
                "zope.component.getUtility")
    def test_listening_ipv4(self, mock_get_utility, mock_process, mock_net):
        from psutil._common import sconn
        conns = [
            sconn(fd=-1, family=2, type=1, laddr=("0.0.0.0", 30),
                  raddr=(), status="LISTEN", pid=None),
            sconn(fd=3, family=2, type=1, laddr=("192.168.5.10", 32783),
                  raddr=("20.40.60.80", 22), status="ESTABLISHED", pid=1234),
            sconn(fd=-1, family=10, type=1, laddr=("::1", 54321),
                  raddr=("::1", 111), status="CLOSE_WAIT", pid=None),
            sconn(fd=3, family=2, type=1, laddr=("0.0.0.0", 17),
                  raddr=(), status="LISTEN", pid=4416)]
        mock_net.return_value = conns
        mock_process.name.return_value = "inetd"
        result = self.authenticator.already_listening(17)
        self.assertTrue(result)
        self.assertEqual(mock_get_utility.call_count, 1)
        mock_process.assert_called_once_with(4416)

    @mock.patch("letsencrypt.plugins.standalone.authenticator.psutil."
                "net_connections")
    @mock.patch("letsencrypt.plugins.standalone.authenticator.psutil.Process")
    @mock.patch("letsencrypt.plugins.standalone.authenticator."
                "zope.component.getUtility")
    def test_listening_ipv6(self, mock_get_utility, mock_process, mock_net):
        from psutil._common import sconn
        conns = [
            sconn(fd=-1, family=2, type=1, laddr=("0.0.0.0", 30),
                  raddr=(), status="LISTEN", pid=None),
            sconn(fd=3, family=2, type=1, laddr=("192.168.5.10", 32783),
                  raddr=("20.40.60.80", 22), status="ESTABLISHED", pid=1234),
            sconn(fd=-1, family=10, type=1, laddr=("::1", 54321),
                  raddr=("::1", 111), status="CLOSE_WAIT", pid=None),
            sconn(fd=3, family=10, type=1, laddr=("::", 12345), raddr=(),
                  status="LISTEN", pid=4420),
            sconn(fd=3, family=2, type=1, laddr=("0.0.0.0", 17),
                  raddr=(), status="LISTEN", pid=4416)]
        mock_net.return_value = conns
        mock_process.name.return_value = "inetd"
        result = self.authenticator.already_listening(12345)
        self.assertTrue(result)
        self.assertEqual(mock_get_utility.call_count, 1)
        mock_process.assert_called_once_with(4420)


class PerformTest(unittest.TestCase):
    """Tests for perform() method."""
    def setUp(self):
        from letsencrypt.plugins.standalone.authenticator import \
            StandaloneAuthenticator
        self.authenticator = StandaloneAuthenticator(config=CONFIG, name=None)

        self.achall1 = achallenges.DVSNI(
            challb=acme_util.chall_to_challb(
                challenges.DVSNI(token=b"foo"), "pending"),
            domain="foo.example.com", account_key=ACCOUNT_KEY)
        self.achall2 = achallenges.DVSNI(
            challb=acme_util.chall_to_challb(
                challenges.DVSNI(token=b"bar"), "pending"),
            domain="bar.example.com", account_key=ACCOUNT_KEY)
        bad_achall = ("This", "Represents", "A Non-DVSNI", "Challenge")
        self.achalls = [self.achall1, self.achall2, bad_achall]

    def test_perform_when_already_listening(self):
        self.authenticator.already_listening = mock.Mock()
        self.authenticator.already_listening.return_value = True
        result = self.authenticator.perform([self.achall1])
        self.assertEqual(result, [None])

    def test_can_perform(self):
        """What happens if start_listener() returns True."""
        self.authenticator.start_listener = mock.Mock()
        self.authenticator.start_listener.return_value = True
        self.authenticator.already_listening = mock.Mock(return_value=False)
        result = self.authenticator.perform(self.achalls)
        self.assertEqual(len(self.authenticator.tasks), 2)
        self.assertTrue(self.achall1.token in self.authenticator.tasks)
        self.assertTrue(self.achall2.token in self.authenticator.tasks)
        self.assertTrue(isinstance(result, list))
        self.assertEqual(len(result), 3)
        self.assertTrue(isinstance(result[0], challenges.ChallengeResponse))
        self.assertTrue(isinstance(result[1], challenges.ChallengeResponse))
        self.assertFalse(result[2])
        self.authenticator.start_listener.assert_called_once_with(
            CONFIG.dvsni_port)

    def test_cannot_perform(self):
        """What happens if start_listener() returns False."""
        self.authenticator.start_listener = mock.Mock()
        self.authenticator.start_listener.return_value = False
        self.authenticator.already_listening = mock.Mock(return_value=False)
        result = self.authenticator.perform(self.achalls)
        self.assertEqual(len(self.authenticator.tasks), 2)
        self.assertTrue(self.achall1.token in self.authenticator.tasks)
        self.assertTrue(self.achall2.token in self.authenticator.tasks)
        self.assertTrue(isinstance(result, list))
        self.assertEqual(len(result), 3)
        self.assertEqual(result, [None, None, False])
        self.authenticator.start_listener.assert_called_once_with(
            CONFIG.dvsni_port)

    def test_perform_with_pending_tasks(self):
        self.authenticator.tasks = {"footoken.acme.invalid": "cert_data"}
        extra_achall = acme_util.DVSNI_P
        self.assertRaises(
            ValueError, self.authenticator.perform, [extra_achall])

    def test_perform_without_challenge_list(self):
        extra_achall = acme_util.DVSNI_P
        # This is wrong because a challenge must be specified.
        self.assertRaises(ValueError, self.authenticator.perform, [])
        # This is wrong because it must be a list, not a bare challenge.
        self.assertRaises(
            ValueError, self.authenticator.perform, extra_achall)
        # This is wrong because the list must contain at least one challenge.
        self.assertRaises(
            ValueError, self.authenticator.perform, range(20))


class StartListenerTest(unittest.TestCase):
    """Tests for start_listener() method."""
    def setUp(self):
        from letsencrypt.plugins.standalone.authenticator import \
            StandaloneAuthenticator
        self.authenticator = StandaloneAuthenticator(config=CONFIG, name=None)

    @mock.patch("letsencrypt.plugins.standalone.authenticator.os.fork")
    def test_start_listener_fork_parent(self, mock_fork):
        self.authenticator.do_parent_process = mock.Mock()
        self.authenticator.do_parent_process.return_value = True
        mock_fork.return_value = 22222
        result = self.authenticator.start_listener(1717)
        # start_listener is expected to return the True or False return
        # value from do_parent_process.
        self.assertTrue(result)
        self.assertEqual(self.authenticator.child_pid, 22222)
        self.authenticator.do_parent_process.assert_called_once_with(1717)

    @mock.patch("letsencrypt.plugins.standalone.authenticator.os.fork")
    def test_start_listener_fork_child(self, mock_fork):
        self.authenticator.do_parent_process = mock.Mock()
        self.authenticator.do_child_process = mock.Mock()
        mock_fork.return_value = 0
        self.authenticator.start_listener(1717)
        self.assertEqual(self.authenticator.child_pid, os.getpid())
        self.authenticator.do_child_process.assert_called_once_with(1717)


class DoParentProcessTest(unittest.TestCase):
    """Tests for do_parent_process() method."""
    def setUp(self):
        from letsencrypt.plugins.standalone.authenticator import \
            StandaloneAuthenticator
        self.authenticator = StandaloneAuthenticator(config=CONFIG, name=None)

    @mock.patch("letsencrypt.plugins.standalone.authenticator."
                "zope.component.getUtility")
    def test_do_parent_process_ok(self, mock_get_utility):
        self.authenticator.subproc_state = "ready"
        result = self.authenticator.do_parent_process(1717)
        self.assertTrue(result)
        self.assertEqual(mock_get_utility.call_count, 1)

    @mock.patch("letsencrypt.plugins.standalone.authenticator."
                "zope.component.getUtility")
    def test_do_parent_process_inuse(self, mock_get_utility):
        self.authenticator.subproc_state = "inuse"
        result = self.authenticator.do_parent_process(1717)
        self.assertFalse(result)
        self.assertEqual(mock_get_utility.call_count, 1)

    @mock.patch("letsencrypt.plugins.standalone.authenticator."
                "zope.component.getUtility")
    def test_do_parent_process_cantbind(self, mock_get_utility):
        self.authenticator.subproc_state = "cantbind"
        result = self.authenticator.do_parent_process(1717)
        self.assertFalse(result)
        self.assertEqual(mock_get_utility.call_count, 1)

    @mock.patch("letsencrypt.plugins.standalone.authenticator."
                "zope.component.getUtility")
    def test_do_parent_process_timeout(self, mock_get_utility):
        # Normally times out in 5 seconds and returns False.  We can
        # now set delay_amount to a lower value so that it times out
        # faster than it would under normal use.
        result = self.authenticator.do_parent_process(1717, delay_amount=1)
        self.assertFalse(result)
        self.assertEqual(mock_get_utility.call_count, 1)


class DoChildProcessTest(unittest.TestCase):
    """Tests for do_child_process() method."""
    def setUp(self):
        from letsencrypt.plugins.standalone.authenticator import \
            StandaloneAuthenticator
        self.authenticator = StandaloneAuthenticator(config=CONFIG, name=None)
        self.cert = achallenges.DVSNI(
            challb=acme_util.chall_to_challb(
                challenges.DVSNI(token=b"abcdef"), "pending"),
            domain="example.com", account_key=ACCOUNT_KEY).gen_cert_and_response(
                key_pem=CHALL_KEY_PEM)[1]
        self.authenticator.private_key = CHALL_KEY
        self.authenticator.tasks = {"abcdef.acme.invalid": self.cert}
        self.authenticator.parent_pid = 12345

    @mock.patch("letsencrypt.plugins.standalone.authenticator.socket.socket")
    @mock.patch("letsencrypt.plugins.standalone.authenticator.os.kill")
    @mock.patch("letsencrypt.plugins.standalone.authenticator.sys.exit")
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
            IndentationError, self.authenticator.do_child_process, 1717)
        mock_exit.assert_called_once_with(1)
        mock_kill.assert_called_once_with(12345, signal.SIGUSR2)

    @mock.patch("letsencrypt.plugins.standalone.authenticator.socket.socket")
    @mock.patch("letsencrypt.plugins.standalone.authenticator.os.kill")
    @mock.patch("letsencrypt.plugins.standalone.authenticator.sys.exit")
    def test_do_child_process_cantbind2(self, mock_exit, mock_kill,
                                        mock_socket):
        mock_exit.side_effect = IndentationError("subprocess would exit here")
        eaccess = socket.error(socket.errno.EADDRINUSE, "Port already in use")
        sample_socket = mock.MagicMock()
        sample_socket.bind.side_effect = eaccess
        mock_socket.return_value = sample_socket
        self.assertRaises(
            IndentationError, self.authenticator.do_child_process, 1717)
        mock_exit.assert_called_once_with(1)
        mock_kill.assert_called_once_with(12345, signal.SIGUSR1)

    @mock.patch("letsencrypt.plugins.standalone.authenticator."
                "socket.socket")
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
            socket.error, self.authenticator.do_child_process, 1717)

    @mock.patch("letsencrypt.plugins.standalone.authenticator."
                "OpenSSL.SSL.Connection")
    @mock.patch("letsencrypt.plugins.standalone.authenticator.socket.socket")
    @mock.patch("letsencrypt.plugins.standalone.authenticator.os.kill")
    def test_do_child_process_success(
            self, mock_kill, mock_socket, mock_connection):
        sample_socket = mock.MagicMock()
        sample_socket.accept.side_effect = _SocketAcceptOnlyNTimes(2)
        mock_socket.return_value = sample_socket
        mock_connection.return_value = mock.MagicMock()
        self.assertRaises(
            CallableExhausted, self.authenticator.do_child_process, 1717)
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
        from letsencrypt.plugins.standalone.authenticator import \
            StandaloneAuthenticator
        self.authenticator = StandaloneAuthenticator(config=CONFIG, name=None)
        self.achall = achallenges.DVSNI(
            challb=acme_util.chall_to_challb(
                challenges.DVSNI(token=b"footoken"), "pending"),
            domain="foo.example.com", account_key="key")
        self.authenticator.tasks = {self.achall.token: "stuff"}
        self.authenticator.child_pid = 12345

    @mock.patch("letsencrypt.plugins.standalone.authenticator.os.kill")
    @mock.patch("letsencrypt.plugins.standalone.authenticator.time.sleep")
    def test_cleanup(self, mock_sleep, mock_kill):
        mock_sleep.return_value = None
        mock_kill.return_value = None

        self.authenticator.cleanup([self.achall])

        mock_kill.assert_called_once_with(12345, signal.SIGINT)
        mock_sleep.assert_called_once_with(1)

    def test_bad_cleanup(self):
        self.assertRaises(
            ValueError, self.authenticator.cleanup, [achallenges.DVSNI(
                challb=acme_util.chall_to_challb(
                    challenges.DVSNI(token=b"badtoken"), "pending"),
                domain="bad.example.com", account_key="key")])


class MoreInfoTest(unittest.TestCase):
    """Tests for more_info() method. (trivially)"""
    def setUp(self):
        from letsencrypt.plugins.standalone.authenticator import (
            StandaloneAuthenticator)
        self.authenticator = StandaloneAuthenticator(config=CONFIG, name=None)

    def test_more_info(self):
        """Make sure exceptions aren't raised."""
        self.authenticator.more_info()


class InitTest(unittest.TestCase):
    """Tests for more_info() method. (trivially)"""
    def setUp(self):
        from letsencrypt.plugins.standalone.authenticator import (
            StandaloneAuthenticator)
        self.authenticator = StandaloneAuthenticator(config=CONFIG, name=None)

    def test_prepare(self):
        """Make sure exceptions aren't raised.

        .. todo:: Add on more once things are setup appropriately.

        """
        self.authenticator.prepare()


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
