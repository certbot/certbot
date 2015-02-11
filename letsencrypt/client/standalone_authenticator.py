"""Standalone authenticator."""
import os
import signal
import socket
import sys
import time

import Crypto.Random
import OpenSSL.crypto
import OpenSSL.SSL
import zope.component
import zope.interface

from letsencrypt.client import challenge_util
from letsencrypt.client import constants
from letsencrypt.client import interfaces


class StandaloneAuthenticator(object):
    # pylint: disable=too-many-instance-attributes
    """Standalone authenticator.

    This authenticator creates its own ephemeral TCP listener on the
    specified port in order to respond to incoming DVSNI challenges from
    the certificate authority. Therefore, it does not rely on any
    existing server program.

    """
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
        """Signal handler for the parent process.

        This handler receives inter-process communication from the
        child process in the form of Unix signals.

        :param int sig: Which signal the process received.

        """
        # subprocess to client READY: SIGIO
        # subprocess to client INUSE: SIGUSR1
        # subprocess to client CANTBIND: SIGUSR2
        if sig == signal.SIGIO:
            self.subproc_state = "ready"
        elif sig == signal.SIGUSR1:
            self.subproc_state = "inuse"
        elif sig == signal.SIGUSR2:
            self.subproc_state = "cantbind"
        else:
            # NOTREACHED
            raise ValueError("Unexpected signal in signal handler")

    def subproc_signal_handler(self, sig, unused_frame):
        """Signal handler for the child process.

        This handler receives inter-process communication from the parent
        process in the form of Unix signals.

        :param int sig: Which signal the process received.

        """
        # client to subprocess CLEANUP : SIGINT
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
        """Used internally to respond to incoming SNI names.

        This method will set a new OpenSSL context object for this
        connection when an incoming connection provides an SNI name
        (in order to serve the appropriate certificate, if any).

        :param connection: The TLS connection object on which the SNI
            extension was received.
        :type connection: :class:`OpenSSL.Connection`

        """
        sni_name = connection.get_servername()
        if sni_name in self.tasks:
            pem_cert = self.tasks[sni_name]
        else:
            # TODO: Should we really present a certificate if we get an
            #       unexpected SNI name? Or should we just disconnect?
            pem_cert = self.tasks.values()[0]
        cert = OpenSSL.crypto.load_certificate(
            OpenSSL.crypto.FILETYPE_PEM, pem_cert)
        new_ctx = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_METHOD)
        new_ctx.set_verify(OpenSSL.SSL.VERIFY_NONE, lambda: False)
        new_ctx.use_certificate(cert)
        new_ctx.use_privatekey(self.private_key)
        connection.set_context(new_ctx)

    def do_parent_process(self, port, delay_amount=5):
        """Perform the parent process side of the TCP listener task.

        This should only be called by :meth:`start_listener`.  We will
        wait up to delay_amount seconds to hear from the child process
        via a signal.

        :param int port: Which TCP port to bind.
        :param float delay_amount: How long in seconds to wait for the
            subprocess to notify us whether it succeeded.

        :returns: ``True`` or ``False`` according to whether we were notified
            that the child process succeeded or failed in binding the port.
        :rtype: bool

        """
        signal.signal(signal.SIGIO, self.client_signal_handler)
        signal.signal(signal.SIGUSR1, self.client_signal_handler)
        signal.signal(signal.SIGUSR2, self.client_signal_handler)

        display = zope.component.getUtility(interfaces.IDisplay)

        start_time = time.time()
        while time.time() < start_time + delay_amount:
            if self.subproc_state == "ready":
                return True
            elif self.subproc_state == "inuse":
                display.generic_notification(
                    "Could not bind TCP port {0} because it is already in "
                    "use it is already in use by another process on this "
                    "system (such as a web server).".format(port))
                return False
            elif self.subproc_state == "cantbind":
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
        """Perform the child process side of the TCP listener task.

        This should only be called by :meth:`start_listener`.

        Normally does not return; instead, the child process exits from
        within this function or from within the child process signal
        handler.

        :param int port: Which TCP port to bind.
        :param key: The private key to use to respond to DVSNI challenge
            requests.
        :type key: `letsencrypt.client.le_util.Key`

        """
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

    def start_listener(self, port, key):
        """Start listener.

        Create a child process which will start a TCP listener on the
        specified port to perform the specified DVSNI challenges.

        :param int port: The TCP port to bind.
        :param key: The private key to use to respond to DVSNI challenge
            requests.
        :type key: :class:`letsencrypt.client.le_util.Key`

        :returns: ``True`` or ``False`` to indicate success or failure creating
            the subprocess.
        :rtype: bool

        """
        fork_result = os.fork()
        Crypto.Random.atfork()
        if fork_result:
            # PARENT process (still the Let's Encrypt client process)
            self.child_pid = fork_result
            # do_parent_process() can return True or False to indicate
            # reported success or failure creating the listener.
            return self.do_parent_process(port)
        else:
            # CHILD process (the TCP listener subprocess)
            self.child_pid = os.getpid()
            # do_child_process() is normally not expected to return but
            # should terminate via sys.exit().
            return self.do_child_process(port, key)

    # IAuthenticator method implementations follow

    def get_chall_pref(self, unused_domain):  # pylint: disable=no-self-use
        """Get challenge preferences."""
        return ["dvsni"]

    def perform(self, chall_list):
        """Perform the challege.

        .. warning::
            For the StandaloneAuthenticator, because there is no convenient
            way to add additional requests, this should only be invoked
            once; subsequent invocations are an error. To perform
            validations for multiple independent sets of domains, a separate
            StandaloneAuthenticator should be instantiated.

        """
        if self.child_pid or self.tasks:
            # We should not be willing to continue with perform
            # if there were existing pending challenges.
            raise ValueError(".perform() was called with pending tasks!")
        results_if_success = []
        results_if_failure = []
        if not chall_list or not isinstance(chall_list, list):
            raise ValueError(".perform() was called without challenge list")
        for chall in chall_list:
            if isinstance(chall, challenge_util.DvsniChall):
                # We will attempt to do it
                name, r_b64 = chall.domain, chall.r_b64
                nonce, key = chall.nonce, chall.key
                cert, s_b64 = challenge_util.dvsni_gen_cert(
                    name, r_b64, nonce, key)
                self.tasks[nonce + constants.DVSNI_DOMAIN_SUFFIX] = cert
                results_if_success.append({"type": "dvsni", "s": s_b64})
                results_if_failure.append(None)
            else:
                # We will not attempt to do this challenge because it
                # is not a type we can handle
                results_if_success.append(False)
                results_if_failure.append(False)
        if not self.tasks:
            raise ValueError("nothing for .perform() to do")
        # Try to do the authentication; note that this creates
        # the listener subprocess via os.fork()
        if self.start_listener(constants.DVSNI_CHALLENGE_PORT, key):
            return results_if_success
        else:
            # TODO: This should probably raise a DVAuthError exception
            #       rather than returning a list of None objects.
            return results_if_failure

    def cleanup(self, chall_list):
        """Clean up.

        If some challenges are removed from the list, the authenticator
        socket will still respond to those challenges. Once all
        challenges have been removed from the list, the listener is
        deactivated and stops listening.

        """
        # Remove this from pending tasks list
        for chall in chall_list:
            assert isinstance(chall, challenge_util.DvsniChall)
            nonce = chall.nonce
            if nonce + constants.DVSNI_DOMAIN_SUFFIX in self.tasks:
                del self.tasks[nonce + constants.DVSNI_DOMAIN_SUFFIX]
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
