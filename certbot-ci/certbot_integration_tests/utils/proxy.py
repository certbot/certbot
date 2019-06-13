#!/usr/bin/env python
import json
import sys

from six.moves import SimpleHTTPServer, socketserver
from six.moves.urllib.request import urlopen


def _create_proxy(ports_mapping):
    class ProxyHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super(ProxyHandler, self).__init__(*args, **kwargs)
            self.ports_mapping = ports_mapping

        def do_GET(self):
            url = '{0}:{1}{2}'.format('http://127.0.0.1', self._select_port(), self.path)
            self.copyfile(urlopen(url), self.wfile)

        def end_headers(self):
            host, _ = self.client_address
            self.send_header('Host', host)
            super(ProxyHandler, self).end_headers()

        def _select_port(self):
            host, _ = self.client_address
            matching = [port for pattern, port in ports_mapping.items()
                        if host.endswith(pattern)]
            return matching[0]

    return ProxyHandler


if __name__ == '__main__':
    port = int(sys.argv[1])
    mapping = json.dumps(sys.argv[2])
    httpd = socketserver.TCPServer(('', port), _create_proxy(mapping))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
