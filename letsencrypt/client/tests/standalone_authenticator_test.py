#!/usr/bin/env python

"""Tests for standalone_authenticator.py."""

import unittest
import mock
import pkg_resources
from letsencrypt.client.challenge_util import DvsniChall


# Classes based on to allow interrupting infinite loop under test
# after one iteration, based on.
# http://igorsobreira.com/2013/03/17/testing-infinite-loops.html

class SocketAcceptOnlyNTimes(object):
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
    """Exception raised when a method is called more than the
    specified number of times."""
    pass


class PackAndUnpackTests(unittest.TestCase):
    """Tests for byte packing and unpacking routines used for TLS
    parsing."""
    def test_pack_and_unpack_bytes(self):
        from letsencrypt.client.standalone_authenticator import \
            unpack_2bytes, unpack_3bytes, pack_2bytes, pack_3bytes
        self.assertEqual(unpack_2bytes("JZ"), 19034)
        self.assertEqual(unpack_2bytes(chr(0)*2), 0)
        self.assertEqual(unpack_2bytes(chr(255)*2), 65535)

        self.assertEqual(unpack_3bytes("abc"), 6382179)
        self.assertEqual(unpack_3bytes(chr(0)*3), 0)
        self.assertEqual(unpack_3bytes(chr(255)*3), 16777215)

        self.assertEqual(pack_2bytes(12), chr(0) + chr(12))
        self.assertEqual(pack_2bytes(1729), chr(6) + chr(193))

        self.assertEqual(pack_3bytes(0), chr(0)*3)
        self.assertEqual(pack_3bytes(12345678), chr(0xbc) + "aN")

    def test_invalid_pack_and_unpack(self):
        from letsencrypt.client.standalone_authenticator import \
            unpack_2bytes, unpack_3bytes, pack_2bytes, pack_3bytes
        with self.assertRaises(AssertionError):
            pack_2bytes(65537)
        with self.assertRaises(AssertionError):
            pack_3bytes(500000000)
        with self.assertRaises(AssertionError):
            unpack_2bytes("foo")
        with self.assertRaises(AssertionError):
            unpack_3bytes("food")


class TLSParseClientHelloTest(unittest.TestCase):
    """Test for tls_parse_client_hello() function."""
    def test_tls_parse_client_hello(self):
        from letsencrypt.client.standalone_authenticator import \
            tls_parse_client_hello
        client_hello = "16030100c4010000c003030cfef9971eda442c60cbb6c397" \
            "7957a81a8ada317e800b7867a8c61f71c40cab000020c02b" \
            "c02fc00ac009c013c014c007c011003300320039002f0035" \
            "000a000500040100007700000010000e00000b7777772e65" \
            "66662e6f7267ff01000100000a0008000600170018001900" \
            "0b00020100002300003374000000100021001f0568322d31" \
            "3408737064792f332e3106737064792f3308687474702f31" \
            "2e31000500050100000000000d0012001004010501020104" \
            "030503020304020202".decode("hex")
        return_value = tls_parse_client_hello(client_hello)
        self.assertEqual(return_value, (chr(0xc0) + chr(0x2b), "www.eff.org"))
        # TODO: The failure cases are extremely numerous and require
        #       constructing TLS ClientHello messages that are individually
        #       defective or surprising in distinct ways. (Each invalid TLS
        #       record is invalid in its own way.)


class TLSGenerateServerHelloTest(unittest.TestCase):
    """Tests for tls_generate_server_hello() function."""
    def test_tls_generate_server_hello(self):
        from letsencrypt.client.standalone_authenticator import \
            tls_generate_server_hello
        server_hello = tls_generate_server_hello("Q!")
        self.assertEqual(server_hello[:11].encode("hex"),
                         '160303002a020000260303')
        self.assertEqual(server_hello[43:], chr(0) + 'Q!' + chr(0))


class TLSGenerateCertMsgTest(unittest.TestCase):
    """Tests for tls_generate_cert_msg() function."""
    def test_tls_generate_cert_msg(self):
        from letsencrypt.client.standalone_authenticator import \
            tls_generate_cert_msg
        cert = pkg_resources.resource_string(__name__,
                                             'testdata/cert.pem')
        cert_msg = tls_generate_cert_msg(cert)
        self.assertEqual(cert_msg.encode("hex"),
                         "16030301ec0b0001e80001e50001e2308201de30820188a003"
                         "02010202020539300d06092a864886f70d01010b0500307731"
                         "0b30090603550406130255533111300f06035504080c084d69"
                         "63686967616e3112301006035504070c09416e6e204172626f"
                         "72312b3029060355040a0c22556e6976657273697479206f66"
                         "204d6963686967616e20616e64207468652045464631143012"
                         "06035504030c0b6578616d706c652e636f6d301e170d313431"
                         "3231313232333434355a170d3134313231383232333434355a"
                         "3077310b30090603550406130255533111300f06035504080c"
                         "084d6963686967616e3112301006035504070c09416e6e2041"
                         "72626f72312b3029060355040a0c22556e6976657273697479"
                         "206f66204d6963686967616e20616e64207468652045464631"
                         "14301206035504030c0b6578616d706c652e636f6d305c300d"
                         "06092a864886f70d0101010500034b003048024100ac7573b4"
                         "51ed1fddae705243fcdfc75bd02c751b14b875010410e51f03"
                         "6545dddfa79f34aefdbee90584df471681d9894bce8e6d1cfa"
                         "9544e8af84744fedc2e50203010001300d06092a864886f70d"
                         "01010b05000341002db8cf421dc0854a4a59ed92c965bebeb3"
                         "25ea411f97cc9dd7e4dd7269d748d3e9513ed7828db63874d9"
                         "ae7a1a8ada02f2404f9fc7ebb13c1af27fa1c36707fa")


class TLSServerHelloDoneTest(unittest.TestCase):
    """Tests for tls_generate_server_hello_done() function."""
    def test_tls_generate_server_hello_done(self):
        from letsencrypt.client.standalone_authenticator import \
            tls_generate_server_hello_done
        self.assertEqual(tls_generate_server_hello_done().encode("hex"), \
            "16030300040e000000")


class ChallPrefTest(unittest.TestCase):
    """Tests for chall_pref() method."""
    def setUp(self):
        from letsencrypt.client.standalone_authenticator import \
            StandaloneAuthenticator
        self.authenticator = StandaloneAuthenticator()

    def test_chall_pref(self):
        self.assertEqual(self.authenticator.get_chall_pref("example.com"),
                         ["dvsni"])


class SNICallbackTest(unittest.TestCase):
    """Tests for sni_callback() method."""
    def setUp(self):
        from letsencrypt.client.standalone_authenticator import \
            StandaloneAuthenticator
        from letsencrypt.client.challenge_util import dvsni_gen_cert
        from letsencrypt.client import le_util
        import OpenSSL.crypto
        from OpenSSL.crypto import FILETYPE_PEM
        self.authenticator = StandaloneAuthenticator()
        r = "x" * 32
        name, r_b64 = "example.com", le_util.jose_b64encode(r)
        RSA256_KEY = pkg_resources.resource_string(__name__,
                                                   'testdata/rsa256_key.pem')
        nonce, key = "abcdef", le_util.Key("foo", RSA256_KEY)
        self.cert = dvsni_gen_cert(name, r_b64, nonce, key)[0]
        private_key = OpenSSL.crypto.load_privatekey(FILETYPE_PEM, key.pem)
        self.authenticator.private_key = private_key
        self.authenticator.tasks = {"abcdef.acme.invalid": self.cert}
        self.authenticator.child_pid = 12345

    def test_real_servername(self):
        import OpenSSL.SSL
        connection = mock.MagicMock()
        connection.get_servername.return_value = "abcdef.acme.invalid"
        self.authenticator.sni_callback(connection)
        self.assertEqual(connection.set_context.call_count, 1)
        called_ctx = connection.set_context.call_args[0][0]
        self.assertIsInstance(called_ctx, OpenSSL.SSL.Context)

    def test_fake_servername(self):
        """Test the behavior of the SNI callback when an unexpected SNI
        name is received.  (Currently the expected behavior in this case
        is to return the "first" certificate with which the listener
        was configured, although they are stored in an unordered data
        structure so this might not be the one that was first in the
        challenge list passed to the perform method.  In the future, this
        might result in dropping the connection instead.)"""
        import OpenSSL.SSL
        connection = mock.MagicMock()
        connection.get_servername.return_value = "example.com"
        self.authenticator.sni_callback(connection)
        self.assertEqual(connection.set_context.call_count, 1)
        called_ctx = connection.set_context.call_args[0][0]
        self.assertIsInstance(called_ctx, OpenSSL.SSL.Context)

class ClientSignalHandlerTest(unittest.TestCase):
    """Tests for client_signal_handler() method."""
    def setUp(self):
        from letsencrypt.client.standalone_authenticator import \
            StandaloneAuthenticator
        self.authenticator = StandaloneAuthenticator()
        self.authenticator.tasks = {"foononce.acme.invalid": "stuff"}
        self.authenticator.child_pid = 12345

    def test_client_signal_handler(self):
        import signal
        self.assertFalse(self.authenticator.subproc_ready)
        self.assertFalse(self.authenticator.subproc_inuse)
        self.assertFalse(self.authenticator.subproc_cantbind)
        self.authenticator.client_signal_handler(signal.SIGIO, None)
        self.assertTrue(self.authenticator.subproc_ready)

        self.authenticator.client_signal_handler(signal.SIGUSR1, None)
        self.assertTrue(self.authenticator.subproc_inuse)

        self.authenticator.client_signal_handler(signal.SIGUSR2, None)
        self.assertTrue(self.authenticator.subproc_cantbind)

        # Testing the unreached path for a signal other than these
        # specified (which can't occur in normal use because this
        # function is only set as a signal handler for the above three
        # signals).
        with self.assertRaises(AssertionError):
            self.authenticator.client_signal_handler(signal.SIGPIPE, None)


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
        import signal
        self.authenticator.ssl_conn = mock.MagicMock()
        self.authenticator.connection = mock.MagicMock()
        self.authenticator.sock = mock.MagicMock()
        self.authenticator.subproc_signal_handler(signal.SIGINT, None)
        self.assertEquals(self.authenticator.ssl_conn.shutdown.call_count, 1)
        self.assertEquals(self.authenticator.ssl_conn.close.call_count, 1)
        self.assertEquals(self.authenticator.connection.close.call_count, 1)
        self.assertEquals(self.authenticator.sock.close.call_count, 1)
        mock_kill.assert_called_once_with(self.authenticator.parent_pid,
                                          signal.SIGUSR1)
        mock_exit.assert_called_once_with(0)

    @mock.patch("letsencrypt.client.standalone_authenticator.os.kill")
    @mock.patch("letsencrypt.client.standalone_authenticator.sys.exit")
    def test_subproc_signal_handler_trouble(self, mock_exit, mock_kill):
        """Test how the signal handler survives attempting to shut down
        a non-existent connection (because none was established or active
        at the time the signal handler tried to perform the cleanup)."""
        import signal
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
        mock_kill.assert_called_once_with(self.authenticator.parent_pid,
                                          signal.SIGUSR1)
        mock_exit.assert_called_once_with(0)


class PerformTest(unittest.TestCase):
    """Tests for perform() method."""
    def setUp(self):
        from letsencrypt.client.standalone_authenticator import \
            StandaloneAuthenticator
        self.authenticator = StandaloneAuthenticator()

    def test_can_perform(self):
        """What happens if start_listener() returns True."""
        from letsencrypt.client import le_util
        RSA256_KEY = pkg_resources.resource_string(__name__,
                                                   'testdata/rsa256_key.pem')
        key = le_util.Key("something", RSA256_KEY)
        chall1 = DvsniChall("foo.example.com", "whee", "foononce", key)
        chall2 = DvsniChall("bar.example.com", "whee", "barnonce", key)
        bad_chall = ("This", "Represents", "A Non-DVSNI", "Challenge")
        self.authenticator.start_listener = mock.Mock()
        self.authenticator.start_listener.return_value = True
        result = self.authenticator.perform([chall1, chall2, bad_chall])
        self.assertEqual(len(self.authenticator.tasks), 2)
        self.assertTrue(
            self.authenticator.tasks.has_key("foononce.acme.invalid"))
        self.assertTrue(
            self.authenticator.tasks.has_key("barnonce.acme.invalid"))
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 3)
        self.assertIsInstance(result[0], dict)
        self.assertIsInstance(result[1], dict)
        self.assertFalse(result[2])
        self.assertTrue(result[0].has_key("s"))
        self.assertTrue(result[1].has_key("s"))
        self.authenticator.start_listener.assert_called_once_with(443, key)

    def test_cannot_perform(self):
        """What happens if start_listener() returns False."""
        from letsencrypt.client import le_util
        RSA256_KEY = pkg_resources.resource_string(__name__,
                                                   'testdata/rsa256_key.pem')
        key = le_util.Key("something", RSA256_KEY)
        chall1 = DvsniChall("foo.example.com", "whee", "foononce", key)
        chall2 = DvsniChall("bar.example.com", "whee", "barnonce", key)
        bad_chall = ("This", "Represents", "A Non-DVSNI", "Challenge")
        self.authenticator.start_listener = mock.Mock()
        self.authenticator.start_listener.return_value = False
        result = self.authenticator.perform([chall1, chall2, bad_chall])
        self.assertEqual(len(self.authenticator.tasks), 2)
        self.assertTrue(
            self.authenticator.tasks.has_key("foononce.acme.invalid"))
        self.assertTrue(
            self.authenticator.tasks.has_key("barnonce.acme.invalid"))
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 3)
        self.assertEqual(result, [None, None, False])
        self.authenticator.start_listener.assert_called_once_with(443, key)

    def test_perform_with_pending_tasks(self):
        self.authenticator.tasks = {"foononce.acme.invalid": "cert_data"}
        extra_challenge = DvsniChall("a", "b", "c", "d")
        with self.assertRaises(Exception):
            self.authenticator.perform([extra_challenge])

    def test_perform_without_challenge_list(self):
        extra_challenge = DvsniChall("a", "b", "c", "d")
        # This is wrong because a challenge must be specified.
        with self.assertRaises(Exception):
            self.authenticator.perform([])
        # This is wrong because it must be a list, not a bare challenge.
        with self.assertRaises(Exception):
            self.authenticator.perform(extra_challenge)
        # This is wrong because the list must contain at least one challenge.
        with self.assertRaises(Exception):
            self.authenticator.perform(range(20))


class StartListenerTest(unittest.TestCase):
    """Tests for start_listener() method."""
    def setUp(self):
        from letsencrypt.client.standalone_authenticator import \
            StandaloneAuthenticator
        self.authenticator = StandaloneAuthenticator()

    @mock.patch("letsencrypt.client.standalone_authenticator.Crypto.Random.atfork")
    @mock.patch("letsencrypt.client.standalone_authenticator.os.fork")
    def test_start_listener_fork_parent(self, mock_fork, mock_atfork):
        self.authenticator.do_parent_process = mock.Mock()
        mock_fork.return_value = 22222
        self.authenticator.start_listener(1717, "key")
        self.assertEqual(self.authenticator.child_pid, 22222)
        self.authenticator.do_parent_process.assert_called_once_with(1717)
        mock_atfork.assert_called_once_with()

    @mock.patch("letsencrypt.client.standalone_authenticator.Crypto.Random.atfork")
    @mock.patch("letsencrypt.client.standalone_authenticator.os.fork")
    def test_start_listener_fork_child(self, mock_fork, mock_atfork):
        import os
        self.authenticator.do_parent_process = mock.Mock()
        self.authenticator.do_child_process = mock.Mock()
        mock_fork.return_value = 0
        self.authenticator.start_listener(1717, "key")
        self.assertEqual(self.authenticator.child_pid, os.getpid())
        self.authenticator.do_child_process.assert_called_once_with(1717,
                                                                    "key")
        mock_atfork.assert_called_once_with()

class DoParentProcessTest(unittest.TestCase):
    """Tests for do_parent_process() method."""
    def setUp(self):
        from letsencrypt.client.standalone_authenticator import \
            StandaloneAuthenticator
        self.authenticator = StandaloneAuthenticator()

    @mock.patch("letsencrypt.client.standalone_authenticator.signal.signal")
    @mock.patch("letsencrypt.client.standalone_authenticator.zope.component.getUtility")
    def test_do_parent_process_ok(self, mock_get_utility, mock_signal):
        self.authenticator.subproc_ready = True
        result = self.authenticator.do_parent_process(1717)
        self.assertTrue(result)
        self.assertEqual(mock_get_utility.call_count, 1)
        self.assertEqual(mock_signal.call_count, 3)

    @mock.patch("letsencrypt.client.standalone_authenticator.signal.signal")
    @mock.patch("letsencrypt.client.standalone_authenticator.zope.component.getUtility")
    def test_do_parent_process_inuse(self, mock_get_utility, mock_signal):
        self.authenticator.subproc_inuse = True
        result = self.authenticator.do_parent_process(1717)
        self.assertFalse(result)
        self.assertEqual(mock_get_utility.call_count, 1)
        self.assertEqual(mock_signal.call_count, 3)

    @mock.patch("letsencrypt.client.standalone_authenticator.signal.signal")
    @mock.patch("letsencrypt.client.standalone_authenticator.zope.component.getUtility")
    def test_do_parent_process_cantbind(self, mock_get_utility, mock_signal):
        self.authenticator.subproc_cantbind = True
        result = self.authenticator.do_parent_process(1717)
        self.assertFalse(result)
        self.assertEqual(mock_get_utility.call_count, 1)
        self.assertEqual(mock_signal.call_count, 3)

    @mock.patch("letsencrypt.client.standalone_authenticator.signal.signal")
    @mock.patch("letsencrypt.client.standalone_authenticator.zope.component.getUtility")
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
        from letsencrypt.client.challenge_util import dvsni_gen_cert
        from letsencrypt.client import le_util
        import OpenSSL.crypto
        from OpenSSL.crypto import FILETYPE_PEM
        self.authenticator = StandaloneAuthenticator()
        r = "x" * 32
        name, r_b64 = "example.com", le_util.jose_b64encode(r)
        RSA256_KEY = pkg_resources.resource_string(__name__,
                                                   'testdata/rsa256_key.pem')
        nonce, key = "abcdef", le_util.Key("foo", RSA256_KEY)
        self.key = key
        self.cert = dvsni_gen_cert(name, r_b64, nonce, key)[0]
        private_key = OpenSSL.crypto.load_privatekey(FILETYPE_PEM, key.pem)
        self.authenticator.private_key = private_key
        self.authenticator.tasks = {"abcdef.acme.invalid": self.cert}
        self.authenticator.parent_pid = 12345

    @mock.patch("letsencrypt.client.standalone_authenticator.socket.socket")
    @mock.patch("letsencrypt.client.standalone_authenticator.os.kill")
    @mock.patch("letsencrypt.client.standalone_authenticator.sys.exit")
    def test_do_child_process_cantbind1(self, mock_exit, mock_kill,
                                        mock_socket):
        import socket, signal
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
        with self.assertRaises(IndentationError):
            self.authenticator.do_child_process(1717, self.key)
        mock_exit.assert_called_once_with(1)
        mock_kill.assert_called_once_with(12345, signal.SIGUSR2)

    @mock.patch("letsencrypt.client.standalone_authenticator.socket.socket")
    @mock.patch("letsencrypt.client.standalone_authenticator.os.kill")
    @mock.patch("letsencrypt.client.standalone_authenticator.sys.exit")
    def test_do_child_process_cantbind2(self, mock_exit, mock_kill,
                                        mock_socket):
        import socket, signal
        mock_exit.side_effect = IndentationError("subprocess would exit here")
        eaccess = socket.error(socket.errno.EADDRINUSE, "Port already in use")
        sample_socket = mock.MagicMock()
        sample_socket.bind.side_effect = eaccess
        mock_socket.return_value = sample_socket
        with self.assertRaises(IndentationError):
            self.authenticator.do_child_process(1717, self.key)
        mock_exit.assert_called_once_with(1)
        mock_kill.assert_called_once_with(12345, signal.SIGUSR1)

    @mock.patch("letsencrypt.client.standalone_authenticator.socket.socket")
    def test_do_child_process_cantbind3(self, mock_socket):
        """Test case where attempt to bind socket results in an unhandled
        socket error.  (The expected behavior is arguably wrong because it
        will crash the program; the reason for the expected behavior is
        that we don't have a way to report arbitrary socket errors.)"""
        import socket
        eio = socket.error(socket.errno.EIO, "Imaginary unhandled error")
        sample_socket = mock.MagicMock()
        sample_socket.bind.side_effect = eio
        mock_socket.return_value = sample_socket
        with self.assertRaises(socket.error):
            self.authenticator.do_child_process(1717, self.key)

    @mock.patch("letsencrypt.client.standalone_authenticator.OpenSSL.SSL.Connection")
    @mock.patch("letsencrypt.client.standalone_authenticator.socket.socket")
    @mock.patch("letsencrypt.client.standalone_authenticator.os.kill")
    def test_do_child_process_success(self, mock_kill, mock_socket, mock_connection):
        import signal
        sample_socket = mock.MagicMock()
        sample_socket.accept.side_effect = SocketAcceptOnlyNTimes(2)
        mock_socket.return_value = sample_socket
        mock_connection.return_value = mock.MagicMock()
        with self.assertRaises(CallableExhausted):
            self.authenticator.do_child_process(1717, self.key)
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
        import signal
        mock_sleep.return_value = None
        mock_kill.return_value = None
        chall = DvsniChall("foo.example.com", "whee", "foononce", "key")
        self.authenticator.cleanup([chall])
        mock_kill.assert_called_once_with(12345, signal.SIGINT)
        mock_sleep.assert_called_once_with(1)

    def test_bad_cleanup(self):
        chall = DvsniChall("bad.example.com", "whee", "badnonce", "key")
        with self.assertRaises(ValueError):
            self.authenticator.cleanup([chall])


if __name__ == '__main__':
    unittest.main()
