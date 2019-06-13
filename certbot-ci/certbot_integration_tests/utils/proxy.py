#!/usr/bin/env python
import json
import sys

from six.moves import SimpleHTTPServer, socketserver
from six.moves.urllib.request import urlopen


class _GracefulTCPServer(socketserver.TCPServer):
    allow_reuse_address = True


def _create_proxy(ports_mapping):
    class ProxyHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):
        def do_GET(self):
            url = '{0}:{1}{2}'.format('http://127.0.0.1', self._select_port(), self.path)
            self.copyfile(urlopen(url), self.wfile)

        def end_headers(self):
            self.send_header('Host', self._get_host())
            SimpleHTTPServer.SimpleHTTPRequestHandler.end_headers(self)

        def _select_port(self):
            host = self._get_host()
            return [port for pattern, port in ports_mapping.items()
                    if host.endswith(pattern)][0]

        def _get_host(self):
            print(vars(self.headers))
            return self.headers.getheader('Host').split(':')[0]

    return ProxyHandler


if __name__ == '__main__':
    http_port = int(sys.argv[1])
    mapping = json.loads(sys.argv[2])
    httpd = _GracefulTCPServer(('', http_port), _create_proxy(mapping))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
