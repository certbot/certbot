#!/usr/bin/env python3
"""A version of Python's SimpleHTTPServer that flushes its output."""
import sys

try:
    from http.server import HTTPServer, SimpleHTTPRequestHandler
except ImportError:
    from BaseHTTPServer import HTTPServer
    from SimpleHTTPServer import SimpleHTTPRequestHandler


def serve_forever(port=0):
    """Spins up an HTTP server on all interfaces and the given port.

    A message is printed to stdout specifying the address and port being used
    by the server.

    :param int port: port number to use.

    """
    server = HTTPServer(('', port), SimpleHTTPRequestHandler)
    print('Serving HTTP on {0} port {1} ...'.format(*server.server_address))
    sys.stdout.flush()
    server.serve_forever()


if __name__ == '__main__':
    kwargs = {}
    if len(sys.argv) > 1:
        kwargs['port'] = int(sys.argv[1])
    serve_forever(**kwargs)
