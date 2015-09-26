"""Standalone Authenticator."""
import collections
import functools
import logging
import random
import socket
import threading

from six.moves import BaseHTTPServer  # pylint: disable=import-error

import OpenSSL
import zope.interface

from acme import challenges
from acme import crypto_util as acme_crypto_util
from acme import standalone as acme_standalone

from letsencrypt import achallenges
from letsencrypt import errors
from letsencrypt import interfaces

from letsencrypt.plugins import common
from letsencrypt.plugins import util

logger = logging.getLogger(__name__)


class ServerManager(object):
    """Standalone servers manager."""

    def __init__(self, certs, simple_http_resources):
        self.servers = {}
        self.certs = certs
        self.simple_http_resources = simple_http_resources

    def run(self, port, tls):
        """Run ACME server on specified ``port``."""
        if port in self.servers:
            return self.servers[port]

        logger.debug("Starting new server at %s (tls=%s)", port, tls)
        handler = acme_standalone.ACMERequestHandler.partial_init(
            self.simple_http_resources)

        if tls:
            cls = functools.partial(
                acme_standalone.HTTPSServer, certs=self.certs)
        else:
            cls = BaseHTTPServer.HTTPServer

        try:
            server = cls(('', port), handler)
        except socket.error as error:
            errors.StandaloneBindError(error, port)

        stop = threading.Event()
        thread = threading.Thread(
            target=self._serve,
            args=(server, stop),
        )
        thread.start()
        self.servers[port] = (server, thread, stop)
        return self.servers[port]

    def _serve(self, server, stop):
        while not stop.is_set():
            server.handle_request()

    def stop(self, port):
        """Stop ACME server running on the specified ``port``."""
        server, thread, stop = self.servers[port]
        stop.set()

        # dummy request to terminate last handle_request()
        sock = socket.socket()
        try:
            sock.connect(server.socket.getsockname())
        except socket.error:
            pass  # thread is probably already finished
        finally:
            sock.close()

        thread.join()
        del self.servers[port]

    def items(self):
        """Return a list of all port, server tuples."""
        return self.servers.items()


class Authenticator(common.Plugin):
    """Standalone Authenticator.

    This authenticator creates its own ephemeral TCP listener on the
    necessary port in order to respond to incoming DVSNI and SimpleHTTP
    challenges from the certificate authority. Therefore, it does not
    rely on any existing server program.

    """
    zope.interface.implements(interfaces.IAuthenticator)
    zope.interface.classProvides(interfaces.IPluginFactory)

    description = "Standalone Authenticator"
    supported_challenges = set([challenges.SimpleHTTP, challenges.DVSNI])

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)

        # one self-signed key for all DVSNI and SimpleHTTP certificates
        self.key = OpenSSL.crypto.PKey()
        self.key.generate_key(OpenSSL.crypto.TYPE_RSA, bits=2048)
        # TODO: generate only when the first SimpleHTTP challenge is solved
        self.simple_http_cert = acme_crypto_util.gen_ss_cert(
            self.key, domains=["temp server"])

        self.responses = {}
        self.servers = {}
        self.served = collections.defaultdict(set)

        # Stuff below is shared across threads (i.e. servers read
        # values, main thread writes). Due to the nature of Cython's
        # GIL, the operations are safe, c.f.
        # https://docs.python.org/2/faq/library.html#what-kinds-of-global-value-mutation-are-thread-safe
        self.certs = {}
        self.simple_http_resources = set()

        self.servers = ServerManager(self.certs, self.simple_http_resources)

    def more_info(self):  # pylint: disable=missing-docstring
        return self.__doc__

    def prepare(self):  # pylint: disable=missing-docstring
        if any(util.already_listening(port) for port in
               (self.config.dvsni_port, self.config.simple_http_port)):
            raise errors.MisconfigurationError(
                "One of the (possibly) required ports is already taken taken.")

    # TODO: add --chall-pref flag
    def get_chall_pref(self, domain):
        # pylint: disable=unused-argument,missing-docstring
        chall_pref = list(self.supported_challenges)
        random.shuffle(chall_pref)  # 50% for each challenge
        return chall_pref

    def perform(self, achalls):  # pylint: disable=missing-docstring
        try:
            return self.perform2(achalls)
        except errors.StandaloneBindError as error:
            display = zope.component.getUtility(interfaces.IDisplay)

            if error.socket_error.errno == socket.errno.EACCES:
                display.notification(
                    "Could not bind TCP port {0} because you don't have "
                    "the appropriate permissions (for example, you "
                    "aren't running this program as "
                    "root).".format(error.port))
            elif error.socket_error.errno == socket.errno.EADDRINUSE:
                display.notification(
                    "Could not bind TCP port {0} because it is already in "
                    "use by another process on this system (such as a web "
                    "server). Please stop the program in question and then "
                    "try again.".format(error.port))
            else:
                raise  # XXX: How to handle unknown errors in binding?

    def perform2(self, achalls):
        """Perform achallenges without IDisplay interaction."""
        responses = []
        tls = not self.config.no_simple_http_tls

        for achall in achalls:
            if isinstance(achall, achallenges.SimpleHTTP):
                server, _, _ = self.servers.run(self.config.simple_http_port, tls=tls)
                response, validation = achall.gen_response_and_validation(tls=tls)
                self.simple_http_resources.add(
                    acme_standalone.SimpleHTTPRequestHandler.SimpleHTTPResource(
                        chall=achall.chall, response=response,
                        validation=validation))
                cert = self.simple_http_cert
                domain = achall.domain
            else:  # DVSNI
                server, _, _ = self.servers.run(self.config.dvsni_port, tls=True)
                response, cert, _ = achall.gen_cert_and_response(self.key)
                domain = response.z_domain
            self.certs[domain] = (self.key, cert)
            self.responses[achall] = response
            self.served[server].add(achall)
            responses.append(response)

        return responses

    def cleanup(self, achalls):  # pylint: disable=missing-docstring
        # reduce self.served and close servers if none challenges are served
        for server, server_achalls in self.served.items():
            for achall in achalls:
                if achall in server_achalls:
                    server_achalls.remove(achall)
        for port, (server, _, _) in self.servers.items():
            if not self.served[server]:
                self.servers.stop(port)
