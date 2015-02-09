#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""An authenticator that doesn't rely on any existing server program,
but instead creates its own ephemeral TCP listener on the specified port
in order to respond to incoming DVSNI challenges from the certificate
authority."""

import zope.interface
import zope.component
from letsencrypt.client import CONFIG
from letsencrypt.client import interfaces
from letsencrypt.client.challenge_util import DvsniChall
from letsencrypt.client.challenge_util import dvsni_gen_cert
import os
import sys
import signal
import time
import socket
import struct
import Crypto.Random
import M2Crypto.X509
import OpenSSL.crypto
import OpenSSL.SSL


def unpack_2bytes(two_bytes):
    """Interpret a two-byte string as an integer.  E.g. 't_' -> 29791."""
    assert len(two_bytes) == 2
    return struct.unpack(">H", two_bytes)[0]


def unpack_3bytes(three_bytes):
    """Interpret a three-byte string as an integer.  E.g. '0M~' -> 3165566."""
    assert len(three_bytes) == 3
    return struct.unpack(">I", chr(0) + three_bytes)[0]


def pack_2bytes(value):
    """Interpret an integer less than 65536 as a two-byte string.  E.g.
    29791 -> 't_'."""
    assert value < 65536
    return struct.pack(">H", value)


def pack_3bytes(value):
    """Interpret an integer less than 16777216 as a three-byte string.
    E.g. '0M~' -> 3165566."""
    assert value < 16777216
    return struct.pack(">I", value)[1:]


# Exclude this function from coverage testing because it is currently
# not used.
def tls_parse_client_hello(tls_record):  # pragma: no cover
    # pylint: disable=too-many-return-statements,too-many-locals,bad-builtin
    # pylint: disable=too-many-branches
    """If possible, parse the specified TLS record as a ClientHello and
    return the first host_name indicated in a Server Name Indication
    extension within that ClientHello.  If the TLS record could not
    be parsed or there is no such extension or host_name present,
    return None.

    :param str tls_record: The TLS record to be parsed (which is assumed
    to contain a single ClientHello handshake message)."""

    # TLS handshake?
    if tls_record[0] != chr(0x16):
        return None

    # TLS version
    tls_version = tls_record[1:3]
    if map(ord, tls_version) not in [[0x03, 0x01], [0x03, 0x02], [0x03, 0x03]]:
        return None

    # TLS record length
    tls_record_len = unpack_2bytes(tls_record[3:5])
    if len(tls_record) < tls_record_len:
        return None

    # Handshake type, length, and version
    handshake_type = tls_record[5]
    if handshake_type != chr(0x01):
        return None
    handshake_len = unpack_3bytes(tls_record[6:9])
    handshake_version = tls_record[9:11]
    handshake = tls_record[11:]

    # Handshake length includes handshake_version (2 bytes)
    if len(handshake) + 2 < handshake_len:
        return None
    if map(ord, handshake_version) not in [[0x03, 0x01], [0x03, 0x02],
                                           [0x03, 0x03]]:
        return None

    # Random
    unused_random = handshake[0:32]

    # Session ID
    session_id_length = ord(handshake[32])
    i = 33
    i += session_id_length

    # Ciphersuites
    ciphersuites_length = unpack_2bytes(handshake[i:i+2])
    if ciphersuites_length >= 2:
        best_ciphersuite = handshake[i+2:i+4]
    else:
        best_ciphersuite = chr(0) + chr(0)
    i += 2
    i += ciphersuites_length

    # Compression methods
    compression_length = ord(handshake[i])
    i += 1
    i += compression_length

    # ClientHello extensions
    extensions_length = unpack_2bytes(handshake[i:i+2])
    i += 2
    if extensions_length < 10:
        # Minimum size of a 1-byte SNI hostname extension
        return None

    while i < len(handshake):
        # XXX  If stated extension lengths are wrong or inconsistent or
        # XXX  if the packet has been truncated in the middle of an
        # XXX  extension, this may crash or hang!  This needs to be updated
        # XXX  to fail cleanly when confronted with inconsistent extension
        # XXX  fields.
        extension_type = handshake[i:i+2]
        if extension_type == "\0\0":
            # SNI
            extension_length = unpack_2bytes(handshake[i+2:i+4])
            i += 4
            unused_server_name_list_length = unpack_2bytes(handshake[i:i+2])
            first_sn_type = handshake[i+2]
            if first_sn_type != "\0":
                # SNI extension referenced something other than a
                # hostname
                return None
            first_sn_length = unpack_2bytes(handshake[i+3:i+5])
            first_sn = handshake[i+5:i+5+first_sn_length]
            return best_ciphersuite, first_sn
        else:
            # Other than SNI
            extension_length = unpack_2bytes(handshake[i+2:i+4])
            i += 4
            i += extension_length
            continue
    return None


def tls_generate_server_hello(ciphersuite):
    """Generate a TLS 1.2 ServerHello message.

    :param ciphersuite str: The ciphersuite that the ServerHello will
    claim to have selected (two bytes)."""

    # Handshake type: ServerHello (0x02)
    server_hello = chr(0x02)
    # ServerHello length (38 bytes based on below)
    server_hello += chr(0x0) + chr(0x0) + chr(38)
    # TLS version (0x0303)
    server_hello += chr(0x03) + chr(0x03)
    # Server Random
    server_hello += Crypto.Random.new().read(32)
    # Session ID length (0)
    server_hello += chr(0x0)
    # Ciphersuite
    server_hello += ciphersuite
    # Compression method (null)
    server_hello += chr(0x0)
    # Extension length (2 bytes) + extensions go here if any extensions
    # are required, BUT if no extensions are present then the extensions
    # and extension length field are both omitted entirely (rather than
    # declaring extension length 0x0000) - see RFC 5246 p. 42.

    # TLS handshake
    tls_record = chr(0x16)
    # TLS version
    tls_record += chr(0x03) + chr(0x03)
    # TLS record length
    assert len(server_hello) < 256
    tls_record += chr(0) + chr(len(server_hello))
    # Append server hello handshake
    tls_record += server_hello
    return tls_record


def tls_generate_cert_msg(cert_pem):
    """Generate a TLS 1.2 Certificate handshake message containing a
    single certificate.

    :param str cert_pem: The certificate to be include in the message (in
    PEM format)."""

    cert_as_der = M2Crypto.X509.load_cert_string(cert_pem).as_der()
    # Handshake type: Certificate (0x0b)
    cert_msg = chr(0x0b)

    cert_msg_length = len(cert_as_der) + 6
    cert_msg += pack_3bytes(cert_msg_length)

    certs_length = len(cert_as_der) + 3
    cert_msg += pack_3bytes(certs_length)

    cert_length = len(cert_as_der)
    cert_msg += pack_3bytes(cert_length)

    cert_msg += cert_as_der

    # TLS handshake
    tls_record = chr(0x16)
    # TLS version
    tls_record += chr(0x03) + chr(0x03)
    # TLS record length
    assert len(cert_msg) < 65536
    tls_record += pack_2bytes(len(cert_msg))
    # Append certificate handshake
    tls_record += cert_msg
    return tls_record


def tls_generate_server_hello_done():
    """Generate a TLS 1.2 ServerHelloDone message."""

    return "16030300040e000000".decode("hex")


class StandaloneAuthenticator(object):
    # pylint: disable=too-many-instance-attributes
    """The StandaloneAuthenticator class itself, which can be invoked
    by the Let's Encrypt client according to the IAuthenticator API
    interface."""
    zope.interface.implements(interfaces.IAuthenticator)

    def __init__(self):
        self.child_pid = None
        self.parent_pid = os.getpid()
        self.subproc_state = None
        self.tasks = {}
        self.sock = None
        self.connection = None
        self.private_key = None
        self.ssl_conn = None

    def client_signal_handler(self, sig, unused_frame):
        """Signal handler for the parent process (to receive inter-process
        communication from the child process in the form of Unix
        signals."""
        # signal handler for use in parent process
        # subprocess → client READY   : SIGIO
        # subprocess → client INUSE   : SIGUSR1
        # subprocess → client CANTBIND: SIGUSR2
        if sig == signal.SIGIO:
            self.subproc_state = "ready"
        elif sig == signal.SIGUSR1:
            self.subproc_state = "inuse"
        elif sig == signal.SIGUSR2:
            self.subproc_state = "cantbind"
        else:
            # NOTREACHED
            assert False

    def subproc_signal_handler(self, sig, unused_frame):
        """Signal handler for the child process (to receive inter-process
        communication from the parent process in the form of Unix
        signals."""
        # signal handler for use in subprocess
        # client → subprocess CLEANUP : SIGINT
        if sig == signal.SIGINT:
            try:
                self.ssl_conn.shutdown()
                self.ssl_conn.close()
            except BaseException:
                # There might not even be any currently active SSL connection.
                pass
            try:
                self.connection.close()
            except BaseException:
                # There might not even be any currently active connection.
                pass
            try:
                self.sock.close()
            except BaseException:
                # Various things can go wrong in the course of closing these
                # connections, but none of them can clearly be usefully
                # reported here and none of them should impede us from
                # exiting as gracefully as possible.
                pass
            os.kill(self.parent_pid, signal.SIGUSR1)
            sys.exit(0)

    def sni_callback(self, connection):
        """Used internally to set a new OpenSSL context object for this
        connection when an incoming connection provides an SNI name (in
        order to serve the appropriate certificate, if any)."""

        sni_name = connection.get_servername()
        if sni_name in self.tasks:
            pem_cert = self.tasks[sni_name]
        else:
            # TODO: Should we really present a certificate if we get an
            #       unexpected SNI name?  Or should we just disconnect?
            pem_cert = self.tasks.values()[0]
        cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM,
                                               pem_cert)
        new_ctx = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_METHOD)
        new_ctx.set_verify(OpenSSL.SSL.VERIFY_NONE, lambda: False)
        new_ctx.use_certificate(cert)
        new_ctx.use_privatekey(self.private_key)
        connection.set_context(new_ctx)

    def do_parent_process(self, port, delay_amount=5):
        """Perform the parent process side of the TCP listener task.  This
        should only be called by start_listener().  We will wait up to
        delay_amount seconds to hear from the child process via a signal."""

        signal.signal(signal.SIGIO, self.client_signal_handler)
        signal.signal(signal.SIGUSR1, self.client_signal_handler)
        signal.signal(signal.SIGUSR2, self.client_signal_handler)
        display = zope.component.getUtility(interfaces.IDisplay)
        start_time = time.time()
        while time.time() < start_time + delay_amount:
            if self.subproc_state == "ready":
                return True
            if self.subproc_state == "inuse":
                display.generic_notification(
                    "Could not bind TCP port {0} because it is already in "
                    "use it is already in use by another process on this "
                    "system (such as a web server).".format(port))
                return False
            if self.subproc_state == "cantbind":
                display.generic_notification(
                    "Could not bind TCP port {0} because you don't have "
                    "the appropriate permissions (for example, you "
                    "aren't running this program as "
                    "root).".format(port))
                return False
            time.sleep(0.1)
        display.generic_notification(
            "Subprocess unexpectedly timed out while trying to bind TCP "
            "port {0}.".format(port))
        return False

    def do_child_process(self, port, key):
        """Perform the child process side of the TCP listener task.  This
        should only be called by start_listener()."""
        signal.signal(signal.SIGINT, self.subproc_signal_handler)
        self.sock = socket.socket()
        try:
            self.sock.bind(("0.0.0.0", port))
        except socket.error, error:
            if error.errno == socket.errno.EACCES:
                # Signal permissions denied to bind TCP port
                os.kill(self.parent_pid, signal.SIGUSR2)
            elif error.errno == socket.errno.EADDRINUSE:
                # Signal TCP port is already in use
                os.kill(self.parent_pid, signal.SIGUSR1)
            else:
                # XXX: How to handle unknown errors in binding?
                raise error
            sys.exit(1)
        # XXX: We could use poll mechanism to handle simultaneous
        # XXX: rather than sequential inbound TCP connections here
        self.sock.listen(1)
        # Signal that we've successfully bound TCP port
        os.kill(self.parent_pid, signal.SIGIO)
        self.private_key = OpenSSL.crypto.load_privatekey(
            OpenSSL.crypto.FILETYPE_PEM, key.pem)

        while True:
            self.connection, _ = self.sock.accept()

            # The code below uses the PyOpenSSL bindings to respond to
            # the client.  This may expose us to bugs and vulnerabilities
            # in OpenSSL (and creates additional dependencies).
            ctx = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_METHOD)
            ctx.set_verify(OpenSSL.SSL.VERIFY_NONE, lambda: False)
            pem_cert = self.tasks.values()[0]
            first_cert = OpenSSL.crypto.load_certificate(
                OpenSSL.crypto.FILETYPE_PEM, pem_cert)
            ctx.use_certificate(first_cert)
            ctx.use_privatekey(self.private_key)
            ctx.set_cipher_list("HIGH")
            ctx.set_tlsext_servername_callback(self.sni_callback)
            self.ssl_conn = OpenSSL.SSL.Connection(ctx, self.connection)
            self.ssl_conn.set_accept_state()
            self.ssl_conn.do_handshake()
            self.ssl_conn.shutdown()
            self.ssl_conn.close()

            # The code below uses the minimal pure Python implementation
            # of TLS ClientHello, ServerHello, and Certificate messages
            # (as an alternative to a full TLS implementation).  It will
            # not reach Finished state with a compliant TLS implementation.
            #
            # client_hello = self.connection.recv(65536)
            # result = tls_parse_client_hello(client_hello)
            # if result is None:
            #    print "No SNI found in ClientHello, dropping connection"
            #    self.connection.close()
            #    continue
            # ciphersuite, sni = result
            # if sni in self.tasks:
            #     pem_cert = self.tasks[sni]
            # else:
            #     # We don't know which cert to send!
            #     print "Unexpected SNI value", sni
            #     # Choose the "first" cert and send it (but maybe we
            #     # should just disconnect instead?)
            #     pem_cert = self.tasks.values()[0]
            # self.connection.send(tls_generate_server_hello(ciphersuite))
            # self.connection.send(tls_generate_cert_msg(pem_cert))
            # self.connection.send(tls_generate_server_hello_done())
            # self.connection.close()

    def start_listener(self, port, key):
        """Create a child process which will start a TCP listener on the
        specified port to perform the specified DVSNI challenges.

        :param int port: The TCP port to bind.
        :param str key: The private key to use (in PEM format).
        """
        fork_result = os.fork()
        Crypto.Random.atfork()
        if fork_result:
            # PARENT process (still the Let's Encrypt client process)
            self.child_pid = fork_result
            self.do_parent_process(port)
        else:
            # CHILD process (the TCP listener subprocess)
            self.child_pid = os.getpid()
            self.do_child_process(port, key)

    # IAuthenticator method implementations follow

    def get_chall_pref(self, unused_domain):
        # pylint: disable=no-self-use
        """IAuthenticator interface method: Return a list of challenge
        types that this authenticator can perform for this domain.  In
        the case of the StandaloneAuthenticator, the only challenge
        type that can ever be performed is dvsni.
        """
        return ["dvsni"]

    def perform(self, chall_list):
        """IAuthenticator interface method: Attempt to perform the
        specified challenges, returning the status of each.  For the
        StandaloneAuthenticator, because there is no convenient way to add
        additional requests, this should only be invoked once; subsequent
        invocations are an error.  To perform validations for multiple
        independent sets of domains, a separate StandaloneAuthenticator
        should be instantiated.
        """
        if self.child_pid or self.tasks:
            # We should not be willing to continue with perform
            # if there were existing pending challenges.
            # TODO: Specify a correct exception subclass.
            raise Exception(".perform() was called with pending tasks!")
        results_if_success = []
        results_if_failure = []
        if not chall_list or not isinstance(chall_list, list):
            # TODO: Specify a correct exception subclass.
            raise Exception(".perform() was called without challenge list")
        for chall in chall_list:
            if isinstance(chall, DvsniChall):
                # We will attempt to do it
                name, r_b64 = chall.domain, chall.r_b64
                nonce, key = chall.nonce, chall.key
                cert, s_b64 = dvsni_gen_cert(name, r_b64, nonce, key)
                self.tasks[nonce + CONFIG.INVALID_EXT] = cert
                results_if_success.append({"type": "dvsni", "s": s_b64})
                results_if_failure.append(None)
            else:
                # We will not attempt to do this challenge because it
                # is not a type we can handle
                results_if_success.append(False)
                results_if_failure.append(False)
        if not self.tasks:
            # TODO: Specify a correct exception subclass.
            raise Exception("nothing for .perform() to do")
        # Try to do the authentication; note that this creates
        # the listener subprocess via os.fork()
        if self.start_listener(CONFIG.PORT, key):
            return results_if_success
        else:
            # TODO: This should probably raise a DVAuthError exception
            #       rather than returning a list of None objects.
            return results_if_failure

    def cleanup(self, chall_list):
        """IAuthenticator interface method: Remove each of the specified
        challenges from the list of challenges that still need to be
        performed.  (In the case of the StandaloneAuthenticator, if some
        challenges are removed from the list, the authenticator socket
        will still respond to those challenges.)  Once all challenges
        have been removed from the list, the listener is deactivated and
        stops listening.
        """
        # Remove this from pending tasks list
        for chall in chall_list:
            assert isinstance(chall, DvsniChall)
            nonce = chall.nonce
            if nonce + CONFIG.INVALID_EXT in self.tasks:
                del self.tasks[nonce + CONFIG.INVALID_EXT]
            else:
                # Could not find the challenge to remove!
                raise ValueError("could not find the challenge to remove")
        if self.child_pid and not self.tasks:
            # There are no remaining challenges, so
            # try to shutdown self.child_pid cleanly.
            # TODO: ignore any signals from child during this process
            os.kill(self.child_pid, signal.SIGINT)
            time.sleep(1)
            # TODO: restore original signal handlers in parent process
            #       by resetting their actions to SIG_DFL
            # print "TCP listener subprocess has been told to shut down"
