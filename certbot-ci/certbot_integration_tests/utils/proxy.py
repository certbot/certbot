#!/usr/bin/env python
# pylint: disable=missing-module-docstring

import http.server as BaseHTTPServer
import json
import re
import sys
from typing import Mapping
from typing import Type

import requests
import urllib.parse
from certbot_integration_tests.utils.misc import GracefulTCPServer


def _create_proxy(mapping: Mapping[str, str]) -> Type[BaseHTTPServer.BaseHTTPRequestHandler]:
    # pylint: disable=missing-function-docstring
    class ProxyHandler(BaseHTTPServer.BaseHTTPRequestHandler):
        # pylint: disable=missing-class-docstring
        def do_GET(self) -> None:
            headers = {key.lower(): value for key, value in self.headers.items()}
            backend = [backend for pattern, backend in mapping.items()
                       if re.match(pattern, headers['host'])][0]
             # Validate that self.path is a safe path (starts with /, no .., no spaces, etc.)
            if not re.match(r'^/[a-zA-Z0-9_\-./]*$', self.path) or '..' in self.path:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b'Invalid path')
                return
            # Safely join backend and path
            url = urllib.parse.urljoin(backend, self.path)
            response = requests.get(url, headers=headers, timeout=10)

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
