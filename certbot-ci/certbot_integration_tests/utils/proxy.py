#!/usr/bin/env python
import json
import sys

import requests
from six.moves import BaseHTTPServer, socketserver


class _GracefulTCPServer(socketserver.TCPServer):
    allow_reuse_address = True


def _get_port(mapping, host):
    fqdn = host.split(':')[0]
    return [port for pattern, port in mapping.items()
            if fqdn.endswith(pattern)][0]


def _create_proxy(mapping):
    class ProxyHandler(BaseHTTPServer.BaseHTTPRequestHandler):
        def do_GET(self):
            headers = {key.lower(): value for key, value in self.headers.items()}
            url = '{0}:{1}{2}'.format('http://127.0.0.1',
                                      _get_port(mapping, headers['host']),
                                      self.path)
            response = requests.get(url, headers=headers)

            self.send_response(response.status_code)
            for key, value in response.headers.items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(response.content)

    return ProxyHandler


if __name__ == '__main__':
    http_port = int(sys.argv[1])
    port_mapping = json.loads(sys.argv[2])
    httpd = _GracefulTCPServer(('', http_port), _create_proxy(port_mapping))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
