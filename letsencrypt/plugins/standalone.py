"""Standalone Authenticator."""
import argparse
import collections
import logging
import socket
import threading

import OpenSSL
import six
import zope.interface

from acme import challenges
from acme import standalone as acme_standalone

from letsencrypt import errors
from letsencrypt import interfaces

from letsencrypt.plugins import common
from letsencrypt.plugins import util

logger = logging.getLogger(__name__)


class ServerManager(object):
    """Standalone servers manager.

    Manager for `ACMEServer` and `ACMETLSServer` instances.

    `certs` and `http_01_resources` correspond to
    `acme.crypto_util.SSLSocket.certs` and
    `acme.crypto_util.SSLSocket.http_01_resources` respectively. All
    created servers share the same certificates and resources, so if
    you're running both TLS and non-TLS instances, HTTP01 handlers
    will serve the same URLs!

    """
    _Instance = collections.namedtuple("_Instance", "server thread")

    def __init__(self, certs, http_01_resources):
        self._instances = {}
        self.certs = certs
        self.http_01_resources = http_01_resources

    def run(self, port, challenge_type):
        """Run ACME server on specified ``port``.

        This method is idempotent, i.e. all calls with the same pair of
        ``(port, challenge_type)`` will reuse the same server.

        :param int port: Port to run the server on.
        :param challenge_type: Subclass of `acme.challenges.Challenge`,
            either `acme.challenge.HTTP01` or `acme.challenges.TLSSNI01`.

        :returns: Server instance.
        :rtype: ACMEServerMixin

        """
        assert challenge_type in (challenges.TLSSNI01, challenges.HTTP01)
        if port in self._instances:
            return self._instances[port].server

        address = ("", port)
        try:
            if challenge_type is challenges.TLSSNI01:
                server = acme_standalone.TLSSNI01Server(address, self.certs)
            else:  # challenges.HTTP01
                server = acme_standalone.HTTP01Server(
                    address, self.http_01_resources)
        except socket.error as error:
            raise errors.StandaloneBindError(error, port)

        thread = threading.Thread(
            # pylint: disable=no-member
            target=server.serve_forever)
        thread.start()

        # if port == 0, then random free port on OS is taken
        # pylint: disable=no-member
        real_port = server.socket.getsockname()[1]
        self._instances[real_port] = self._Instance(server, thread)
        return server

    def stop(self, port):
        """Stop ACME server running on the specified ``port``.

        :param int port:

        """
        instance = self._instances[port]
        logger.debug("Stopping server at %s:%d...",
                     *instance.server.socket.getsockname()[:2])
        instance.server.shutdown()
        instance.thread.join()
        del self._instances[port]

    def running(self):
        """Return all running instances.

        Once the server is stopped using `stop`, it will not be
        returned.

        :returns: Mapping from ``port`` to ``server``.
        :rtype: tuple

        """
        return dict((port, instance.server) for port, instance
                    in six.iteritems(self._instances))


SUPPORTED_CHALLENGES = [challenges.TLSSNI01, challenges.HTTP01]


def supported_challenges_validator(data):
    """Supported challenges validator for the `argparse`.

    It should be passed as `type` argument to `add_argument`.

    """
    challs = data.split(",")
    unrecognized = [name for name in challs
                    if name not in challenges.Challenge.TYPES]
    if unrecognized:
        raise argparse.ArgumentTypeError(
            "Unrecognized challenges: {0}".format(", ".join(unrecognized)))

    choices = set(chall.typ for chall in SUPPORTED_CHALLENGES)
    if not set(challs).issubset(choices):
        raise argparse.ArgumentTypeError(
            "Plugin does not support the following (valid) "
            "challenges: {0}".format(", ".join(set(challs) - choices)))

    return data


class Authenticator(common.Plugin):
    """Standalone Authenticator.

    This authenticator creates its own ephemeral TCP listener on the
    necessary port in order to respond to incoming tls-sni-01 and http-01
    challenges from the certificate authority. Therefore, it does not
    rely on any existing server program.
    """
    zope.interface.implements(interfaces.IAuthenticator)
    zope.interface.classProvides(interfaces.IPluginFactory)

    description = "Automatically use a temporary webserver"

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)

        # one self-signed key for all tls-sni-01 certificates
        self.key = OpenSSL.crypto.PKey()
        self.key.generate_key(OpenSSL.crypto.TYPE_RSA, bits=2048)

        self.served = collections.defaultdict(set)

        # Stuff below is shared across threads (i.e. servers read
        # values, main thread writes). Due to the nature of CPython's
        # GIL, the operations are safe, c.f.
        # https://docs.python.org/2/faq/library.html#what-kinds-of-global-value-mutation-are-thread-safe
        self.certs = {}
        self.http_01_resources = set()

        self.servers = ServerManager(self.certs, self.http_01_resources)

    @classmethod
    def add_parser_arguments(cls, add):
        add("supported-challenges",
            help="Supported challenges. Preferred in the order they are listed.",
            type=supported_challenges_validator,
            default=",".join(chall.typ for chall in SUPPORTED_CHALLENGES))

    @property
    def supported_challenges(self):
        """Challenges supported by this plugin."""
        return [challenges.Challenge.TYPES[name] for name in
                self.conf("supported-challenges").split(",")]

    @property
    def _necessary_ports(self):
        necessary_ports = set()
        if challenges.HTTP01 in self.supported_challenges:
            necessary_ports.add(self.config.http01_port)
        if challenges.TLSSNI01 in self.supported_challenges:
            necessary_ports.add(self.config.tls_sni_01_port)
        return necessary_ports

    def more_info(self):  # pylint: disable=missing-docstring
        return("This authenticator creates its own ephemeral TCP listener "
               "on the necessary port in order to respond to incoming "
               "tls-sni-01 and http-01 challenges from the certificate "
               "authority. Therefore, it does not rely on any existing "
               "server program.")

    def prepare(self):  # pylint: disable=missing-docstring
        pass

    def get_chall_pref(self, domain):
        # pylint: disable=unused-argument,missing-docstring
        return self.supported_challenges

    def perform(self, achalls):  # pylint: disable=missing-docstring
        if any(util.already_listening(port) for port in self._necessary_ports):
            raise errors.MisconfigurationError(
                "At least one of the (possibly) required ports is "
                "already taken.")

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

        for achall in achalls:
            if isinstance(achall.chall, challenges.HTTP01):
                server = self.servers.run(
                    self.config.http01_port, challenges.HTTP01)
                response, validation = achall.response_and_validation()
                self.http_01_resources.add(
                    acme_standalone.HTTP01RequestHandler.HTTP01Resource(
                        chall=achall.chall, response=response,
                        validation=validation))
            else:  # tls-sni-01
                server = self.servers.run(
                    self.config.tls_sni_01_port, challenges.TLSSNI01)
                response, (cert, _) = achall.response_and_validation(
                    cert_key=self.key)
                self.certs[response.z_domain] = (self.key, cert)
            self.served[server].add(achall)
            responses.append(response)

        return responses

    def cleanup(self, achalls):  # pylint: disable=missing-docstring
        # reduce self.served and close servers if none challenges are served
        for server, server_achalls in self.served.items():
            for achall in achalls:
                if achall in server_achalls:
                    server_achalls.remove(achall)
        for port, server in six.iteritems(self.servers.running()):
            if not self.served[server]:
                self.servers.stop(port)
