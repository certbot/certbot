#!/usr/bin/env python
# pylint: disable=missing-module-docstring

import http.server as BaseHTTPServer
import json
import re
import sys
from typing import Mapping

import requests

from certbot_integration_tests.utils.misc import GracefulTCPServer


def _create_proxy(mapping: Mapping[str, str]) -> type[BaseHTTPServer.BaseHTTPRequestHandler]:
    # pylint: disable=missing-function-docstring
    class ProxyHandler(BaseHTTPServer.BaseHTTPRequestHandler):
        # pylint: disable=missing-class-docstring
        def do_GET(self) -> None:
            headers = {key.lower(): value for key, value in self.headers.items()}
            host = headers['host']
            for pattern, backend in mapping.items():
                if re.match(pattern, host):
                    response = requests.get(backend + self.path, headers=headers, timeout=10)

                    self.send_response(response.status_code)
                    for key, value in response.headers.items():
                        self.send_header(key, value)
                    self.end_headers()
                    self.wfile.write(response.content)
                    return

            # We should never hit this if the tests are written correctly, but if we do, this may
            # be helpful debugging output.
            print(f"proxy.py: do_GET for {host}: No backend")
            self.send_response(500, f"No backend")
            self.end_headers()
            self.wfile.write(bytes(f"No backend found for {host}\n", 'utf-8'))

    return ProxyHandler


if __name__ == '__main__':
    http_port = int(sys.argv[1])
    port_mapping = json.loads(sys.argv[2])
    httpd = GracefulTCPServer(('', http_port), _create_proxy(port_mapping))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
