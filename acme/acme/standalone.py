"""Support for standalone client challenge solvers. """
import argparse
import collections
import functools
import logging
import os
import socket
import sys
import threading

from six.moves import BaseHTTPServer  # type: ignore  # pylint: disable=import-error
from six.moves import http_client  # pylint: disable=import-error
from six.moves import socketserver  # type: ignore  # pylint: disable=import-error

import OpenSSL

from acme import challenges
from acme import crypto_util


logger = logging.getLogger(__name__)

# six.moves.* | pylint: disable=no-member,attribute-defined-outside-init
# pylint: disable=too-few-public-methods,no-init


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
            # pylint: disable=protected-access
            "method", crypto_util._DEFAULT_TLSSNI01_SSL_METHOD)
        self.allow_reuse_address = kwargs.pop("allow_reuse_address", True)
        socketserver.TCPServer.__init__(self, *args, **kwargs)

    def _wrap_sock(self):
        self.socket = crypto_util.SSLSocket(
            self.socket, certs=self.certs, method=self.method)

    def server_bind(self):  # pylint: disable=missing-docstring
        self._wrap_sock()
        return socketserver.TCPServer.server_bind(self)


class ACMEServerMixin:  # pylint: disable=old-style-class
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
        self.threads = []
        self.servers = []

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
                server = ServerClass(*new_args, **kwargs) # pylint: disable=star-args
            except socket.error:
                logger.debug("Failed to bind to %s:%s using %s", new_address[0],
                    new_address[1], "IPv6" if ip_version else "IPv4")
            else:
                self.servers.append(server)
                # If two servers are set up and port 0 was passed in, ensure we always
                # bind to the same port for both servers.
                port = server.socket.getsockname()[1]
        if len(self.servers) == 0:
            raise socket.error("Could not bind to IPv4 or IPv6.")

    def serve_forever(self):
        """Wraps socketserver.TCPServer.serve_forever"""
        for server in self.servers:
            thread = threading.Thread(
                # pylint: disable=no-member
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


class TLSSNI01Server(TLSServer, ACMEServerMixin):
    """TLSSNI01 Server."""

    def __init__(self, server_address, certs, ipv6=False):
        TLSServer.__init__(
            self, server_address, BaseRequestHandlerWithLogging, certs=certs, ipv6=ipv6)


class TLSSNI01DualNetworkedServers(BaseDualNetworkedServers):
    """TLSSNI01Server Wrapper. Tries everything for both. Failures for one don't
       affect the other."""

    def __init__(self, *args, **kwargs):
        BaseDualNetworkedServers.__init__(self, TLSSNI01Server, *args, **kwargs)


class BaseRequestHandlerWithLogging(socketserver.BaseRequestHandler):
    """BaseRequestHandler with logging."""

    def log_message(self, format, *args):  # pylint: disable=redefined-builtin
        """Log arbitrary message."""
        logger.debug("%s - - %s", self.client_address[0], format % args)

    def handle(self):
        """Handle request."""
        self.log_message("Incoming request")
        socketserver.BaseRequestHandler.handle(self)


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
        socketserver.BaseRequestHandler.__init__(self, *args, **kwargs)

    def log_message(self, format, *args):  # pylint: disable=redefined-builtin
        """Log arbitrary message."""
        logger.debug("%s - - %s", self.client_address[0], format % args)

    def handle(self):
        """Handle request."""
        self.log_message("Incoming request")
        BaseHTTPServer.BaseHTTPRequestHandler.handle(self)

    def do_GET(self):  # pylint: disable=invalid-name,missing-docstring
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


def simple_tls_sni_01_server(cli_args, forever=True):
    """Run simple standalone TLSSNI01 server."""
    logging.basicConfig(level=logging.DEBUG)

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-p", "--port", default=0, help="Port to serve at. By default "
        "picks random free port.")
    args = parser.parse_args(cli_args[1:])

    certs = {}

    _, hosts, _ = next(os.walk('.'))
    for host in hosts:
        with open(os.path.join(host, "cert.pem")) as cert_file:
            cert_contents = cert_file.read()
        with open(os.path.join(host, "key.pem")) as key_file:
            key_contents = key_file.read()
        certs[host.encode()] = (
            OpenSSL.crypto.load_privatekey(
                OpenSSL.crypto.FILETYPE_PEM, key_contents),
            OpenSSL.crypto.load_certificate(
                OpenSSL.crypto.FILETYPE_PEM, cert_contents))

    server = TLSSNI01Server(('', int(args.port)), certs=certs)
    logger.info("Serving at https://%s:%s...", *server.socket.getsockname()[:2])
    if forever:  # pragma: no cover
        server.serve_forever()
    else:
        server.handle_request()


if __name__ == "__main__":
    sys.exit(simple_tls_sni_01_server(sys.argv))  # pragma: no cover
