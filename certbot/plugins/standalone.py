"""Standalone Authenticator."""
import collections
import logging
import socket
# https://github.com/python/typeshed/blob/master/stdlib/2and3/socket.pyi
from socket import errno as socket_errors  # type: ignore

import OpenSSL  # pylint: disable=unused-import
import six
import zope.interface

from acme import challenges
from acme import standalone as acme_standalone
# pylint: disable=unused-import, no-name-in-module
from acme.magic_typing import DefaultDict, Dict, Set, Tuple, List, Type, TYPE_CHECKING

from certbot import achallenges  # pylint: disable=unused-import
from certbot import errors
from certbot import interfaces

from certbot.plugins import common

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    ServedType = DefaultDict[
        acme_standalone.BaseDualNetworkedServers,
        Set[achallenges.KeyAuthorizationAnnotatedChallenge]
    ]

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
    def __init__(self, certs, http_01_resources):
        self._instances = {}  # type: Dict[int, acme_standalone.BaseDualNetworkedServers]
        self.certs = certs
        self.http_01_resources = http_01_resources

    def run(self, port, challenge_type, listenaddr=""):
        """Run ACME server on specified ``port``.

        This method is idempotent, i.e. all calls with the same pair of
        ``(port, challenge_type)`` will reuse the same server.

        :param int port: Port to run the server on.
        :param challenge_type: Subclass of `acme.challenges.Challenge`,
            currently only `acme.challenge.HTTP01`.
        :param str listenaddr: (optional) The address to listen on. Defaults to all addrs.

        :returns: DualNetworkedServers instance.
        :rtype: ACMEServerMixin

        """
        assert challenge_type == challenges.HTTP01
        if port in self._instances:
            return self._instances[port]

        address = (listenaddr, port)
        try:
            servers = acme_standalone.HTTP01DualNetworkedServers(
                address, self.http_01_resources)
        except socket.error as error:
            raise errors.StandaloneBindError(error, port)

        servers.serve_forever()

        # if port == 0, then random free port on OS is taken
        # pylint: disable=no-member
        # both servers, if they exist, have the same port
        real_port = servers.getsocknames()[0][1]
        self._instances[real_port] = servers
        return servers

    def stop(self, port):
        """Stop ACME server running on the specified ``port``.

        :param int port:

        """
        instance = self._instances[port]
        for sockname in instance.getsocknames():
            logger.debug("Stopping server at %s:%d...",
                         *sockname[:2])
        instance.shutdown_and_server_close()
        del self._instances[port]

    def running(self):
        """Return all running instances.

        Once the server is stopped using `stop`, it will not be
        returned.

        :returns: Mapping from ``port`` to ``servers``.
        :rtype: tuple

        """
        return self._instances.copy()


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(common.Plugin):
    """Standalone Authenticator.

    This authenticator creates its own ephemeral TCP listener on the
    necessary port in order to respond to incoming http-01
    challenges from the certificate authority. Therefore, it does not
    rely on any existing server program.
    """

    description = "Spin up a temporary webserver"

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)

        self.served = collections.defaultdict(set)  # type: ServedType

        # Stuff below is shared across threads (i.e. servers read
        # values, main thread writes). Due to the nature of CPython's
        # GIL, the operations are safe, c.f.
        # https://docs.python.org/2/faq/library.html#what-kinds-of-global-value-mutation-are-thread-safe
        self.certs = {}  # type: Dict[bytes, Tuple[OpenSSL.crypto.PKey, OpenSSL.crypto.X509]]
        self.http_01_resources = set() \
        # type: Set[acme_standalone.HTTP01RequestHandler.HTTP01Resource]

        self.servers = ServerManager(self.certs, self.http_01_resources)

    @classmethod
    def add_parser_arguments(cls, add):
        pass  # No additional argument for the standalone plugin parser

    def more_info(self):  # pylint: disable=missing-docstring
        return("This authenticator creates its own ephemeral TCP listener "
               "on the necessary port in order to respond to incoming "
               "http-01 challenges from the certificate authority. Therefore, "
               "it does not rely on any existing server program.")

    def prepare(self):  # pylint: disable=missing-docstring
        pass

    def get_chall_pref(self, domain):
        # pylint: disable=unused-argument,missing-docstring
        return [challenges.HTTP01]

    def perform(self, achalls):  # pylint: disable=missing-docstring
        return [self._try_perform_single(achall) for achall in achalls]

    def _try_perform_single(self, achall):
        while True:
            try:
                return self._perform_single(achall)
            except errors.StandaloneBindError as error:
                _handle_perform_error(error)

    def _perform_single(self, achall):
        servers, response = self._perform_http_01(achall)
        self.served[servers].add(achall)
        return response

    def _perform_http_01(self, achall):
        port = self.config.http01_port
        addr = self.config.http01_address
        servers = self.servers.run(port, challenges.HTTP01, listenaddr=addr)
        response, validation = achall.response_and_validation()
        resource = acme_standalone.HTTP01RequestHandler.HTTP01Resource(
            chall=achall.chall, response=response, validation=validation)
        self.http_01_resources.add(resource)
        return servers, response

    def cleanup(self, achalls):  # pylint: disable=missing-docstring
        # reduce self.served and close servers if no challenges are served
        for unused_servers, server_achalls in self.served.items():
            for achall in achalls:
                if achall in server_achalls:
                    server_achalls.remove(achall)
        for port, servers in six.iteritems(self.servers.running()):
            if not self.served[servers]:
                self.servers.stop(port)


def _handle_perform_error(error):
    if error.socket_error.errno == socket_errors.EACCES:
        raise errors.PluginError(
            "Could not bind TCP port {0} because you don't have "
            "the appropriate permissions (for example, you "
            "aren't running this program as "
            "root).".format(error.port))
    elif error.socket_error.errno == socket_errors.EADDRINUSE:
        display = zope.component.getUtility(interfaces.IDisplay)
        msg = (
            "Could not bind TCP port {0} because it is already in "
            "use by another process on this system (such as a web "
            "server). Please stop the program in question and "
            "then try again.".format(error.port))
        should_retry = display.yesno(msg, "Retry",
                                     "Cancel", default=False)
        if not should_retry:
            raise errors.PluginError(msg)
    else:
        raise error
