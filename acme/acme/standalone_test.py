"""Tests for acme.standalone."""
import os
import threading
import time
import unittest

from six.moves import http_client  # pylint: disable=import-error
from six.moves import socketserver  # pylint: disable=import-error

import requests

from acme import challenges
from acme import crypto_util
from acme import jose
from acme import test_util


class TLSServerTest(unittest.TestCase):
    """Tests for acme.standalone.TLSServer."""

    def test_bind(self):  # pylint: disable=no-self-use
        from acme.standalone import TLSServer
        server = TLSServer(
            ('', 0), socketserver.BaseRequestHandler, bind_and_activate=True)
        server.server_close()  # pylint: disable=no-member


class ACMEServerMixinTest(unittest.TestCase):
    """Tests for acme.standalone.ACMEServerMixin."""

    def test_shutdown2_not_running(self):
        from acme.standalone import ACMEServer
        server = ACMEServer(("", 0), socketserver.BaseRequestHandler)
        server.shutdown2()
        server.shutdown2()


class ACMEServerTest(unittest.TestCase):
    """Test for acme.standalone.ACMEServer."""

    def test_init(self):
        from acme.standalone import ACMEServer
        server = ACMEServer(("", 0), socketserver.BaseRequestHandler)
        # pylint: disable=protected-access
        self.assertFalse(server._stopped)


class ACMESimpleHTTPTLSServerTestEndToEnd(unittest.TestCase):
    """End-to-end test for ACME TLS server with SimpleHTTP."""

    def setUp(self):
        self.certs = {
            b'localhost': (test_util.load_pyopenssl_private_key('rsa512_key.pem'),
                           # pylint: disable=protected-access
                           test_util.load_cert('cert.pem')._wrapped),
        }
        self.account_key = jose.JWK.load(
            test_util.load_vector('rsa1024_key.pem'))

        from acme.standalone import ACMETLSServer
        from acme.standalone import ACMERequestHandler
        self.resources = set()
        handler = ACMERequestHandler.partial_init(
            simple_http_resources=self.resources)
        self.server = ACMETLSServer(('', 0), handler, certs=self.certs)
        self.server_thread = threading.Thread(
            # pylint: disable=no-member
            target=self.server.serve_forever2)
        self.server_thread.start()

        self.port = self.server.socket.getsockname()[1]

    def tearDown(self):
        self.server.shutdown2()
        self.server_thread.join()

    def test_index(self):
        response = requests.get(
            'https://localhost:{0}'.format(self.port), verify=False)
        self.assertEqual(response.text, 'ACME standalone client')
        self.assertTrue(response.ok)

    def test_404(self):
        response = requests.get(
            'https://localhost:{0}/foo'.format(self.port), verify=False)
        self.assertEqual(response.status_code, http_client.NOT_FOUND)

    def test_dvsni(self):
        cert = crypto_util.probe_sni(
            b'localhost', *self.server.socket.getsockname())
        self.assertEqual(jose.ComparableX509(cert),
                         jose.ComparableX509(self.certs[b'localhost'][1]))

    def _test_simple_http(self, add):
        chall = challenges.SimpleHTTP(token=(b'x' * 16))
        response = challenges.SimpleHTTPResponse(tls=True)

        from acme.standalone import SimpleHTTPRequestHandler
        resource = SimpleHTTPRequestHandler.SimpleHTTPResource(
            chall=chall, response=response, validation=response.gen_validation(
                chall, self.account_key))
        if add:
            self.resources.add(resource)
        return resource.response.simple_verify(
            resource.chall, 'localhost', self.account_key.public_key(),
            port=self.port)

    def test_simple_http_found(self):
        self.assertTrue(self._test_simple_http(add=True))

    def test_simple_http_not_found(self):
        self.assertFalse(self._test_simple_http(add=False))


class TestSimpleServer(unittest.TestCase):
    """Tests for acme.standalone.simple_server."""

    TEST_CWD = os.path.join(os.path.dirname(__file__), '..', 'examples', 'standalone')

    def setUp(self):
        from acme.standalone import simple_server
        self.thread = threading.Thread(target=simple_server, kwargs={
            'cli_args': ('xxx', '--port', '1234'),
            'forever': False,
        })
        self.old_cwd = os.getcwd()
        os.chdir(self.TEST_CWD)
        self.thread.start()

    def tearDown(self):
        os.chdir(self.old_cwd)
        self.thread.join()

    def test_it(self):
        max_attempts = 5
        while max_attempts:
            max_attempts -= 1
            try:
                response = requests.get('https://localhost:1234', verify=False)
            except requests.ConnectionError:
                self.assertTrue(max_attempts > 0, "Timeout!")
                time.sleep(1)  # wait until thread starts
            else:
                self.assertEqual(response.text, 'ACME standalone client')
                break


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
