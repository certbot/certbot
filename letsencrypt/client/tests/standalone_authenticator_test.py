#!/usr/bin/env python

"""Tests for standalone_authenticator.py."""

import unittest
import mock
import pkg_resources
from letsencrypt.client.challenge_util import DvsniChall


class PackAndUnpackTests(unittest.TestCase):
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


class TLSParseClientHelloTest(unittest.TestCase):
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
    def test_tls_generate_server_hello(self):
        from letsencrypt.client.standalone_authenticator import \
            tls_generate_server_hello
        server_hello = tls_generate_server_hello("Q!")
        self.assertEqual(server_hello[:11].encode("hex"),
            '160303002a020000260303')
        self.assertEqual(server_hello[43:], chr(0) + 'Q!' + chr(0))


class TLSServerHelloDoneTest(unittest.TestCase):
    def test_tls_generate_server_hello_done(self):
        from letsencrypt.client.standalone_authenticator import \
            tls_generate_server_hello_done
        self.assertEqual(tls_generate_server_hello_done().encode("hex"), \
            "16030300040e000000")


class ChallPrefTest(unittest.TestCase):
    def setUp(self):
        from letsencrypt.client.standalone_authenticator import \
            StandaloneAuthenticator
        self.authenticator = StandaloneAuthenticator()

    def test_chall_pref(self):
        self.assertEqual(self.authenticator.get_chall_pref("example.com"),
                    ["dvsni"])


class SNICallbackTest(unittest.TestCase):
    def setUp(self):
        from letsencrypt.client.standalone_authenticator import \
            StandaloneAuthenticator
        from letsencrypt.client.challenge_util import dvsni_gen_cert
        from letsencrypt.client import le_util
        import OpenSSL.crypto
        self.authenticator = StandaloneAuthenticator()
        r = "x" * 32
        name, r_b64 = "example.com", le_util.jose_b64encode(r)
        RSA256_KEY = pkg_resources.resource_string(__name__,
            'testdata/rsa256_key.pem')
        nonce, key = "abcdef", le_util.Key("foo", RSA256_KEY)
        self.cert = dvsni_gen_cert(name, r_b64, nonce, key)[0]
        self.authenticator.private_key = OpenSSL.crypto.load_privatekey(
                OpenSSL.crypto.FILETYPE_PEM, key.pem)
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


class ClientSignalHandlerTest(unittest.TestCase):
    def setUp(self):
        from letsencrypt.client.standalone_authenticator import \
            StandaloneAuthenticator
        self.authenticator = StandaloneAuthenticator()
        self.authenticator.tasks = {"foononce.acme.invalid": "stuff"}
        self.authenticator.child_pid = 12345

    def test_client_signal_handler(self):
        import signal
        self.assertEquals(self.authenticator.subproc_ready, False)
        self.assertEquals(self.authenticator.subproc_inuse, False)
        self.assertEquals(self.authenticator.subproc_cantbind, False)
        self.authenticator.client_signal_handler(signal.SIGIO, None)
        self.assertEquals(self.authenticator.subproc_ready, True)

        self.authenticator.client_signal_handler(signal.SIGUSR1, None)
        self.assertEquals(self.authenticator.subproc_inuse, True)

        self.authenticator.client_signal_handler(signal.SIGUSR2, None)
        self.assertEquals(self.authenticator.subproc_cantbind, True)

class SubprocSignalHandlerTest(unittest.TestCase):
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
        # TODO: We should test that we correctly survive each of the above
        #       raising an exception of some kind (since they're likely to
        #       do so in practice if there's no live TLS connection at the
        #       time the subprocess is told to clean up).
        self.assertEquals(mock_kill.call_count, 1)
        self.assertEquals(mock_exit.call_count, 1)


class CleanupTest(unittest.TestCase):
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
        chall = DvsniChall("foo.example.com", "whee", "foononce", "key")
        self.authenticator.cleanup([chall])
        self.assertEqual(mock_kill.call_count, 1)
        self.assertEqual(mock_sleep.call_count, 1)

    def test_bad_cleanup(self):
        chall = DvsniChall("bad.example.com", "whee", "badnonce", "key")
        with self.assertRaises(ValueError):
            self.authenticator.cleanup([chall])


if __name__ == '__main__':
    unittest.main()


# TODO: Unit tests for the following functions
# def tls_generate_cert_msg(cert_pem):
# def start_listener(self, port, key):
# def perform(self, chall_list):
