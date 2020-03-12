"""Support for standalone client challenge solvers. """
import collections
import functools
import logging
import socket
import threading

from six.moves import BaseHTTPServer  # type: ignore
from six.moves import http_client
from six.moves import socketserver  # type: ignore

from acme import challenges
from acme import crypto_util
from acme.magic_typing import List

logger = logging.getLogger(__name__)


class TLSServer(socketserver.TCPServer):
    """Generic TLS Server."""

    def __init__(self, *args, **kwargs):
        self.ipv6 = kwargs.pop("ipv6", False)
        if self.ipv6:
            self.address_family = socket.AF_INET6
        else:
            self.address_family = socket.AF_INET
        self.certs = kwargs.pop("certs", {})
        self.method = kwargs.pop(
            "method", crypto_util._DEFAULT_SSL_METHOD)
        self.allow_reuse_address = kwargs.pop("allow_reuse_address", True)
        socketserver.TCPServer.__init__(self, *args, **kwargs)

    def _wrap_sock(self):
        self.socket = crypto_util.SSLSocket(
            self.socket, certs=self.certs, method=self.method)

    def server_bind(self):
        self._wrap_sock()
        return socketserver.TCPServer.server_bind(self)


class ACMEServerMixin:
    """ACME server common settings mixin."""
    # TODO: c.f. #858
    server_version = "ACME client standalone challenge solver"
    allow_reuse_address = True


class BaseDualNetworkedServers(object):
    """Base class for a pair of IPv6 and IPv4 servers that tries to do everything
       it's asked for both servers, but where failures in one server don't
       affect the other.

       If two servers are instantiated, they will serve on the same port.
       """

    def __init__(self, ServerClass, server_address, *remaining_args, **kwargs):
        port = server_address[1]
        self.threads = [] # type: List[threading.Thread]
        self.servers = [] # type: List[ACMEServerMixin]

        # Must try True first.
        # Ubuntu, for example, will fail to bind to IPv4 if we've already bound
        # to IPv6. But that's ok, since it will accept IPv4 connections on the IPv6
        # socket. On the other hand, FreeBSD will successfully bind to IPv4 on the
        # same port, which means that server will accept the IPv4 connections.
        # If Python is compiled without IPv6, we'll error out but (probably) successfully
        # create the IPv4 server.
        for ip_version in [True, False]:
            try:
                kwargs["ipv6"] = ip_version
                new_address = (server_address[0],) + (port,) + server_address[2:]
                new_args = (new_address,) + remaining_args
                server = ServerClass(*new_args, **kwargs)
                logger.debug(
                    "Successfully bound to %s:%s using %s", new_address[0],
                    new_address[1], "IPv6" if ip_version else "IPv4")
            except socket.error:
                if self.servers:
                    # Already bound using IPv6.
                    logger.debug(
                        "Certbot wasn't able to bind to %s:%s using %s, this "
                        "is often expected due to the dual stack nature of "
                        "IPv6 socket implementations.",
                        new_address[0], new_address[1],
                        "IPv6" if ip_version else "IPv4")
                else:
                    logger.debug(
                        "Failed to bind to %s:%s using %s", new_address[0],
                        new_address[1], "IPv6" if ip_version else "IPv4")
            else:
                self.servers.append(server)
                # If two servers are set up and port 0 was passed in, ensure we always
                # bind to the same port for both servers.
                port = server.socket.getsockname()[1]
        if not self.servers:
            raise socket.error("Could not bind to IPv4 or IPv6.")

    def serve_forever(self):
        """Wraps socketserver.TCPServer.serve_forever"""
        for server in self.servers:
            thread = threading.Thread(
                target=server.serve_forever)
            thread.start()
            self.threads.append(thread)

    def getsocknames(self):
        """Wraps socketserver.TCPServer.socket.getsockname"""
        return [server.socket.getsockname() for server in self.servers]

    def shutdown_and_server_close(self):
        """Wraps socketserver.TCPServer.shutdown, socketserver.TCPServer.server_close, and
           threading.Thread.join"""
        for server in self.servers:
            server.shutdown()
            server.server_close()
        for thread in self.threads:
            thread.join()
        self.threads = []


class HTTPServer(BaseHTTPServer.HTTPServer):
    """Generic HTTP Server."""

    def __init__(self, *args, **kwargs):
        self.ipv6 = kwargs.pop("ipv6", False)
        if self.ipv6:
            self.address_family = socket.AF_INET6
        else:
            self.address_family = socket.AF_INET
        BaseHTTPServer.HTTPServer.__init__(self, *args, **kwargs)


class HTTP01Server(HTTPServer, ACMEServerMixin):
    """HTTP01 Server."""

    def __init__(self, server_address, resources, ipv6=False):
        HTTPServer.__init__(
            self, server_address, HTTP01RequestHandler.partial_init(
                simple_http_resources=resources), ipv6=ipv6)


class HTTP01DualNetworkedServers(BaseDualNetworkedServers):
    """HTTP01Server Wrapper. Tries everything for both. Failures for one don't
       affect the other."""

    def __init__(self, *args, **kwargs):
        BaseDualNetworkedServers.__init__(self, HTTP01Server, *args, **kwargs)


class HTTP01RequestHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    """HTTP01 challenge handler.

    Adheres to the stdlib's `socketserver.BaseRequestHandler` interface.

    :ivar set simple_http_resources: A set of `HTTP01Resource`
        objects. TODO: better name?

    """
    HTTP01Resource = collections.namedtuple(
        "HTTP01Resource", "chall response validation")

    def __init__(self, *args, **kwargs):
        self.simple_http_resources = kwargs.pop("simple_http_resources", set())
        BaseHTTPServer.BaseHTTPRequestHandler.__init__(self, *args, **kwargs)

    def log_message(self, format, *args):  # pylint: disable=redefined-builtin
        """Log arbitrary message."""
        logger.debug("%s - - %s", self.client_address[0], format % args)

    def handle(self):
        """Handle request."""
        self.log_message("Incoming request")
        BaseHTTPServer.BaseHTTPRequestHandler.handle(self)

    def do_GET(self):  # pylint: disable=invalid-name,missing-function-docstring
        if self.path == "/":
            self.handle_index()
        elif self.path.startswith("/" + challenges.HTTP01.URI_ROOT_PATH):
            self.handle_simple_http_resource()
        else:
            self.handle_404()

    def handle_index(self):
        """Handle index page."""
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(self.server.server_version.encode())

    def handle_404(self):
        """Handler 404 Not Found errors."""
        self.send_response(http_client.NOT_FOUND, message="Not Found")
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(b"404")

    def handle_simple_http_resource(self):
        """Handle HTTP01 provisioned resources."""
        for resource in self.simple_http_resources:
            if resource.chall.path == self.path:
                self.log_message("Serving HTTP01 with token %r",
                                 resource.chall.encode("token"))
                self.send_response(http_client.OK)
                self.end_headers()
                self.wfile.write(resource.validation.encode())
                return
        else:  # pylint: disable=useless-else-on-loop
            self.log_message("No resources to serve")
        self.log_message("%s does not correspond to any resource. ignoring",
                         self.path)

    @classmethod
    def partial_init(cls, simple_http_resources):
        """Partially initialize this handler.

        This is useful because `socketserver.BaseServer` takes
        uninitialized handler and initializes it with the current
        request.

        """
        return functools.partial(
            cls, simple_http_resources=simple_http_resources)
