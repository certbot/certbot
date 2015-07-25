"""Standalone authenticator."""
import os
import psutil
import signal
import socket
import sys
import time

import OpenSSL
import zope.component
import zope.interface

from acme import challenges

from letsencrypt import achallenges
from letsencrypt import crypto_util
from letsencrypt import interfaces

from letsencrypt.plugins import common


class StandaloneAuthenticator(common.Plugin):
    # pylint: disable=too-many-instance-attributes
    """Standalone authenticator.

    This authenticator creates its own ephemeral TCP listener on the
    specified port in order to respond to incoming DVSNI challenges from
    the certificate authority. Therefore, it does not rely on any
    existing server program.

    :param OpenSSL.crypto.PKey private_key: DVSNI challenge certificate
        key.
    :param sni_names: Mapping from z_domain (`bytes`) to PEM-encoded
        certificate (`bytes`).

    """
    zope.interface.implements(interfaces.IAuthenticator)
    zope.interface.classProvides(interfaces.IPluginFactory)

    description = "Standalone Authenticator"

    def __init__(self, *args, **kwargs):
        super(StandaloneAuthenticator, self).__init__(*args, **kwargs)
        self.child_pid = None
        self.parent_pid = os.getpid()
        self.subproc_state = None
        self.tasks = {}
        self.sni_names = {}
        self.sock = None
        self.connection = None
        self.key_pem = crypto_util.make_key(bits=2048)
        self.private_key = OpenSSL.crypto.load_privatekey(
            OpenSSL.crypto.FILETYPE_PEM, self.key_pem)
        self.ssl_conn = None

    def prepare(self):
        """There is nothing left to setup.

        .. todo:: This should probably do the port check

        """

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
        if sni_name in self.sni_names:
            pem_cert = self.sni_names[sni_name]
        else:
            # TODO: Should we really present a certificate if we get an
            #       unexpected SNI name? Or should we just disconnect?
            pem_cert = next(self.sni_names.itervalues())
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
        display = zope.component.getUtility(interfaces.IDisplay)

        start_time = time.time()
        while time.time() < start_time + delay_amount:
            if self.subproc_state == "ready":
                return True
            elif self.subproc_state == "inuse":
                display.notification(
                    "Could not bind TCP port {0} because it is already in "
                    "use by another process on this system (such as a web "
                    "server). Please stop the program in question and then "
                    "try again.".format(port))
                return False
            elif self.subproc_state == "cantbind":
                display.notification(
                    "Could not bind TCP port {0} because you don't have "
                    "the appropriate permissions (for example, you "
                    "aren't running this program as "
                    "root).".format(port))
                return False
            time.sleep(0.1)

        display.notification(
            "Subprocess unexpectedly timed out while trying to bind TCP "
            "port {0}.".format(port))

        return False

    def do_child_process(self, port):
        """Perform the child process side of the TCP listener task.

        This should only be called by :meth:`start_listener`.

        Normally does not return; instead, the child process exits from
        within this function or from within the child process signal
        handler.

        :param int port: Which TCP port to bind.

        """
        signal.signal(signal.SIGINT, self.subproc_signal_handler)
        self.sock = socket.socket()
        # SO_REUSEADDR flag tells the kernel to reuse a local socket
        # in TIME_WAIT state, without waiting for its natural timeout
        # to expire.
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
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

    def start_listener(self, port):
        """Start listener.

        Create a child process which will start a TCP listener on the
        specified port to perform the specified DVSNI challenges.

        :param int port: The TCP port to bind.

        :returns: ``True`` or ``False`` to indicate success or failure creating
            the subprocess.
        :rtype: bool

        """
        # In order to avoid a race condition, we set the signal handler
        # that will be needed by the parent process now, and undo this
        # action if we turn out to be the child process.  (This needs
        # to happen before the fork because the child will send one of
        # these signals to the parent almost immediately after the
        # fork, and the parent must already be ready to receive it.)
        signal.signal(signal.SIGIO, self.client_signal_handler)
        signal.signal(signal.SIGUSR1, self.client_signal_handler)
        signal.signal(signal.SIGUSR2, self.client_signal_handler)

        sys.stdout.flush()
        fork_result = os.fork()
        if fork_result:
            # PARENT process (still the Let's Encrypt client process)
            self.child_pid = fork_result
            # do_parent_process() can return True or False to indicate
            # reported success or failure creating the listener.
            return self.do_parent_process(port)
        else:
            # CHILD process (the TCP listener subprocess)
            # Undo the parent's signal handler settings, which aren't
            # applicable to us.
            signal.signal(signal.SIGIO, signal.SIG_DFL)
            signal.signal(signal.SIGUSR1, signal.SIG_DFL)
            signal.signal(signal.SIGUSR2, signal.SIG_DFL)

            self.child_pid = os.getpid()
            # do_child_process() is normally not expected to return but
            # should terminate via sys.exit().
            return self.do_child_process(port)

    def already_listening(self, port):  # pylint: disable=no-self-use
        """Check if a process is already listening on the port.

        If so, also tell the user via a display notification.

        .. warning::
            On some operating systems, this function can only usefully be
            run as root.

        :param int port: The TCP port in question.
        :returns: True or False."""

        listeners = [conn.pid for conn in psutil.net_connections()
                     if conn.status == 'LISTEN' and
                     conn.type == socket.SOCK_STREAM and
                     conn.laddr[1] == port]
        try:
            if listeners and listeners[0] is not None:
                # conn.pid may be None if the current process doesn't have
                # permission to identify the listening process!  Additionally,
                # listeners may have more than one element if separate
                # sockets have bound the same port on separate interfaces.
                # We currently only have UI to notify the user about one
                # of them at a time.
                pid = listeners[0]
                name = psutil.Process(pid).name()
                display = zope.component.getUtility(interfaces.IDisplay)
                display.notification(
                    "The program {0} (process ID {1}) is already listening "
                    "on TCP port {2}. This will prevent us from binding to "
                    "that port. Please stop the {0} program temporarily "
                    "and then try again.".format(name, pid, port))
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            # Perhaps the result of a race where the process could have
            # exited or relinquished the port (NoSuchProcess), or the result
            # of an OS policy where we're not allowed to look up the process
            # name (AccessDenied).
            pass
        return False

    # IAuthenticator method implementations follow

    def get_chall_pref(self, unused_domain):  # pylint: disable=no-self-use
        """Get challenge preferences.

        IAuthenticator interface method get_chall_pref.
        Return a list of challenge types that this authenticator
        can perform for this domain.  In the case of the
        StandaloneAuthenticator, the only challenge type that can ever
        be performed is dvsni.

        :returns: A list containing only 'dvsni'.

        """
        return [challenges.DVSNI]

    def perform(self, achalls):
        """Perform the challenge.

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
        if not achalls or not isinstance(achalls, list):
            raise ValueError(".perform() was called without challenge list")
        # TODO: "bits" should be user-configurable
        for achall in achalls:
            if isinstance(achall, achallenges.DVSNI):
                # We will attempt to do it
                response, cert_pem, _ = achall.gen_cert_and_response(
                    key_pem=self.key_pem)
                self.sni_names[response.z_domain] = cert_pem
                self.tasks[achall.token] = cert_pem
                results_if_success.append(response)
                results_if_failure.append(None)
            else:
                # We will not attempt to do this challenge because it
                # is not a type we can handle
                results_if_success.append(False)
                results_if_failure.append(False)
        if not self.tasks:
            raise ValueError("nothing for .perform() to do")

        if self.already_listening(self.config.dvsni_port):
            # If we know a process is already listening on this port,
            # tell the user, and don't even attempt to bind it.  (This
            # test is Linux-specific and won't indicate that the port
            # is bound if invoked on a different operating system.)
            return results_if_failure
        # Try to do the authentication; note that this creates
        # the listener subprocess via os.fork()
        if self.start_listener(self.config.dvsni_port):
            return results_if_success
        else:
            # TODO: This should probably raise a DVAuthError exception
            #       rather than returning a list of None objects.
            return results_if_failure

    def cleanup(self, achalls):
        """Clean up.

        If some challenges are removed from the list, the authenticator
        socket will still respond to those challenges. Once all
        challenges have been removed from the list, the listener is
        deactivated and stops listening.

        """
        # Remove this from pending tasks list
        for achall in achalls:
            assert isinstance(achall, achallenges.DVSNI)
            if achall.token in self.tasks:
                del self.tasks[achall.token]
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

    def more_info(self):  # pylint: disable=no-self-use
        """Human-readable string that describes the Authenticator."""
        return ("The Standalone Authenticator uses PyOpenSSL to listen "
                "on port {port} and perform DVSNI challenges. Once a "
                "certificate is attained, it will be saved in the "
                "(TODO) current working directory.{linesep}{linesep}"
                "TCP port {port} must be available in order to use the "
                "Standalone Authenticator.".format(
                    linesep=os.linesep, port=self.config.dvsni_port))
