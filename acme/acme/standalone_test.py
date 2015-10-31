"""Tests for acme.standalone."""
import os
import shutil
import threading
import tempfile
import time
import unittest

from six.moves import http_client  # pylint: disable=import-error
from six.moves import socketserver  # pylint: disable=import-error

import requests

from acme import challenges
from acme import crypto_util
from acme import errors
from acme import jose
from acme import test_util


class TLSServerTest(unittest.TestCase):
    """Tests for acme.standalone.TLSServer."""

    def test_bind(self):  # pylint: disable=no-self-use
        from acme.standalone import TLSServer
        server = TLSServer(
            ('', 0), socketserver.BaseRequestHandler, bind_and_activate=True)
        server.server_close()  # pylint: disable=no-member


class DVSNIServerTest(unittest.TestCase):
    """Test for acme.standalone.DVSNIServer."""

    def setUp(self):
        self.certs = {
            b'localhost': (test_util.load_pyopenssl_private_key('rsa512_key.pem'),
                           # pylint: disable=protected-access
                           test_util.load_cert('cert.pem')._wrapped),
        }
        from acme.standalone import DVSNIServer
        self.server = DVSNIServer(("", 0), certs=self.certs)
        # pylint: disable=no-member
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()  # pylint: disable=no-member
        self.thread.join()

    def test_it(self):
        host, port = self.server.socket.getsockname()[:2]
        cert = crypto_util.probe_sni(b'localhost', host=host, port=port, timeout=1)
        self.assertEqual(jose.ComparableX509(cert),
                         jose.ComparableX509(self.certs[b'localhost'][1]))


class SimpleHTTPServerTest(unittest.TestCase):
    """Tests for acme.standalone.SimpleHTTPServer."""

    def setUp(self):
        self.account_key = jose.JWK.load(
            test_util.load_vector('rsa1024_key.pem'))
        self.resources = set()

        from acme.standalone import SimpleHTTPServer
        self.server = SimpleHTTPServer(('', 0), resources=self.resources)

        # pylint: disable=no-member
        self.port = self.server.socket.getsockname()[1]
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()  # pylint: disable=no-member
        self.thread.join()

    def test_index(self):
        response = requests.get(
            'http://localhost:{0}'.format(self.port), verify=False)
        self.assertEqual(
            response.text, 'ACME client standalone challenge solver')
        self.assertTrue(response.ok)

    def test_404(self):
        response = requests.get(
            'http://localhost:{0}/foo'.format(self.port), verify=False)
        self.assertEqual(response.status_code, http_client.NOT_FOUND)

    def _test_simple_http(self, add):
        chall = challenges.SimpleHTTP(token=(b'x' * 16))
        response = challenges.SimpleHTTPResponse(tls=False)

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


class TestSimpleDVSNIServer(unittest.TestCase):
    """Tests for acme.standalone.simple_dvsni_server."""

    def setUp(self):
        # mirror ../examples/standalone
        self.test_cwd = tempfile.mkdtemp()
        localhost_dir = os.path.join(self.test_cwd, 'localhost')
        os.makedirs(localhost_dir)
        shutil.copy(test_util.vector_path('cert.pem'), localhost_dir)
        shutil.copy(test_util.vector_path('rsa512_key.pem'),
                    os.path.join(localhost_dir, 'key.pem'))

        from acme.standalone import simple_dvsni_server
        self.port = 1234
        self.thread = threading.Thread(target=simple_dvsni_server, kwargs={
            'cli_args': ('xxx', '--port', str(self.port)),
            'forever': False,
        })
        self.old_cwd = os.getcwd()
        os.chdir(self.test_cwd)
        self.thread.start()

    def tearDown(self):
        os.chdir(self.old_cwd)
        self.thread.join()
        shutil.rmtree(self.test_cwd)

    def test_it(self):
        max_attempts = 5
        while max_attempts:
            max_attempts -= 1
            try:
                cert = crypto_util.probe_sni(b'localhost', b'0.0.0.0', self.port)
            except errors.Error:
                self.assertTrue(max_attempts > 0, "Timeout!")
                time.sleep(1)  # wait until thread starts
            else:
                self.assertEqual(jose.ComparableX509(cert),
                                 test_util.load_cert('cert.pem'))
                break


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
