"""Tests for acme.standalone."""
import mock
import os
import shutil
import socket
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
from acme import standalone
from acme import test_util


class IPv6EnabledTest(unittest.TestCase):
    """Tests for acme.standalone.ipv6_enabled."""

    @mock.patch.object(socket, 'socket')
    def test_has_ipv6(self, socket_mock):
        socket_mock.return_value = mock.Mock()
        self.assertTrue(standalone.ipv6_enabled(12))

    @mock.patch.object(socket, 'socket')
    def test_cannot_bind_ipv6(self, socket_mock):
        socket_mock.side_effect = socket.error
        self.assertFalse(standalone.ipv6_enabled(12))


class TLSServerTest(unittest.TestCase):
    """Tests for acme.standalone.TLSServer."""

    @mock.patch.object(standalone, 'ipv6_enabled')
    def test_bind_has_ipv6(self, mock_ipv6):
        mock_ipv6.return_value = True
        from acme.standalone import TLSServer
        server = TLSServer(
            ('', 0), socketserver.BaseRequestHandler, bind_and_activate=True)
        server.server_close()  # pylint: disable=no-member
        self.assertEqual(server.address_family, socket.AF_INET6)

    @mock.patch.object(standalone, 'ipv6_enabled')
    def test_bind_no_ipv6(self, mock_ipv6):
        mock_ipv6.return_value = False
        from acme.standalone import TLSServer
        server = TLSServer(
            ('', 0), socketserver.BaseRequestHandler, bind_and_activate=True)
        server.server_close()  # pylint: disable=no-member
        self.assertEqual(server.address_family, socket.AF_INET)


class TLSSNI01ServerTest(unittest.TestCase):
    """Test for acme.standalone.TLSSNI01Server."""

    def setUp(self):
        self.certs = {b'localhost': (
            test_util.load_pyopenssl_private_key('rsa2048_key.pem'),
            test_util.load_cert('rsa2048_cert.pem'),
        )}
        from acme.standalone import TLSSNI01Server
        self.server = TLSSNI01Server(("", 0), certs=self.certs)
        # pylint: disable=no-member
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()  # pylint: disable=no-member
        self.thread.join()

    def test_it(self):
        host, port = self.server.socket.getsockname()[:2]
        cert = crypto_util.probe_sni(
            b'localhost', host=host, port=port, timeout=1)
        self.assertEqual(jose.ComparableX509(cert),
                         jose.ComparableX509(self.certs[b'localhost'][1]))


class HTTP01ServerTest(unittest.TestCase):
    """Tests for acme.standalone.HTTP01Server."""

    def setUp(self):
        self.account_key = jose.JWK.load(
            test_util.load_vector('rsa1024_key.pem'))
        self.resources = set()

    def _setup_server(self, ipv6=True):
        # Run tests with IPv6 enabled by default, but allow toggling off to
        # test fallback capability.
        with mock.patch.object(standalone, 'ipv6_enabled', return_value=ipv6):
            from acme.standalone import HTTP01Server
            self.server = HTTP01Server(('', 0), resources=self.resources)  # pylint: disable=attribute-defined-outside-init

            # pylint: disable=no-member
            self.port = self.server.socket.getsockname()[1]  # pylint: disable=attribute-defined-outside-init
            self.thread = threading.Thread(target=self.server.serve_forever)  # pylint: disable=attribute-defined-outside-init
            self.thread.start()

    def tearDown(self):
        self.server.shutdown()  # pylint: disable=no-member
        self.thread.join()

    def test_index(self):
        self._setup_server()
        response = requests.get(
            'http://localhost:{0}'.format(self.port), verify=False)
        self.assertEqual(
            response.text, 'ACME client standalone challenge solver')
        self.assertTrue(response.ok)
        self.assertEqual(self.server.address_family, socket.AF_INET6)

    def test_index_no_ipv6(self):
        self._setup_server(ipv6=False)
        response = requests.get(
            'http://localhost:{0}'.format(self.port), verify=False)
        self.assertEqual(
            response.text, 'ACME client standalone challenge solver')
        self.assertTrue(response.ok)
        self.assertEqual(self.server.address_family, socket.AF_INET)

    def test_404(self):
        self._setup_server()
        response = requests.get(
            'http://localhost:{0}/foo'.format(self.port), verify=False)
        self.assertEqual(response.status_code, http_client.NOT_FOUND)
        self.assertEqual(self.server.address_family, socket.AF_INET6)

    def _test_http01(self, add):
        self._setup_server()
        chall = challenges.HTTP01(token=(b'x' * 16))
        response, validation = chall.response_and_validation(self.account_key)

        from acme.standalone import HTTP01RequestHandler
        resource = HTTP01RequestHandler.HTTP01Resource(
            chall=chall, response=response, validation=validation)
        if add:
            self.resources.add(resource)
        return resource.response.simple_verify(
            resource.chall, 'localhost', self.account_key.public_key(),
            port=self.port)

    def test_http01_found(self):
        self.assertTrue(self._test_http01(add=True))
        self.assertEqual(self.server.address_family, socket.AF_INET6)

    def test_http01_not_found(self):
        self.assertFalse(self._test_http01(add=False))
        self.assertEqual(self.server.address_family, socket.AF_INET6)


class TestSimpleTLSSNI01Server(unittest.TestCase):
    """Tests for acme.standalone.simple_tls_sni_01_server."""

    def setUp(self):
        # mirror ../examples/standalone
        self.test_cwd = tempfile.mkdtemp()
        localhost_dir = os.path.join(self.test_cwd, 'localhost')
        os.makedirs(localhost_dir)
        shutil.copy(test_util.vector_path('rsa2048_cert.pem'),
                    os.path.join(localhost_dir, 'cert.pem'))
        shutil.copy(test_util.vector_path('rsa2048_key.pem'),
                    os.path.join(localhost_dir, 'key.pem'))

        from acme.standalone import simple_tls_sni_01_server
        self.port = 1234
        self.thread = threading.Thread(
            target=simple_tls_sni_01_server, kwargs={
                'cli_args': ('xxx', '--port', str(self.port)),
                'forever': False,
            },
        )
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
                cert = crypto_util.probe_sni(
                    b'localhost', b'0.0.0.0', self.port)
            except errors.Error:
                self.assertTrue(max_attempts > 0, "Timeout!")
                time.sleep(1)  # wait until thread starts
            else:
                self.assertEqual(jose.ComparableX509(cert),
                                 test_util.load_comparable_cert(
                                     'rsa2048_cert.pem'))
                break


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
