#!/usr/bin/env python
import json
import sys
import re

import requests
from six.moves import BaseHTTPServer

from certbot_integration_tests.utils.misc import GracefulTCPServer


def _create_proxy(mapping):
    class ProxyHandler(BaseHTTPServer.BaseHTTPRequestHandler):
        def do_GET(self):
            headers = {key.lower(): value for key, value in self.headers.items()}
            backend = [backend for pattern, backend in mapping.items()
                       if re.match(pattern, headers['host'])][0]
            response = requests.get(backend + self.path, headers=headers)

            self.send_response(response.status_code)
            for key, value in response.headers.items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(response.content)

    return ProxyHandler


if __name__ == '__main__':
    http_port = int(sys.argv[1])
    port_mapping = json.loads(sys.argv[2])
    httpd = GracefulTCPServer(('', http_port), _create_proxy(port_mapping))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
