#!/usr/bin/env python
import json
import sys

from six.moves import SimpleHTTPServer, socketserver
from six.moves.urllib.request import Request, urlopen


class _GracefulTCPServer(socketserver.TCPServer):
    allow_reuse_address = True


def _select_port(mapping, host):
    fqdn = host.split(':')[0]
    return [port for pattern, port in mapping.items()
            if fqdn.endswith(pattern)][0]


def _create_proxy(mapping):
    class ProxyHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):
        def do_GET(self):
            host = self.headers.get('Host')
            url = '{0}:{1}{2}'.format('http://127.0.0.1', _select_port(mapping, host), self.path)
            req = Request(url, headers={'Host': host})
            response = urlopen(req)

            self.send_response(response.getcode())
            for key, value in response.getinfo():
                self.send_header(key, value)
            self.end_headers()
            self.copyfile(urlopen(url), self.wfile)

    return ProxyHandler


if __name__ == '__main__':
    http_port = int(sys.argv[1])
    port_mapping = json.loads(sys.argv[2])
    httpd = _GracefulTCPServer(('', http_port), _create_proxy(port_mapping))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
