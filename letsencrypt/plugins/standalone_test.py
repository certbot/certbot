"""Tests for letsencrypt.plugins.standalone."""
import socket
import unittest

from letsencrypt import errors


class ServerManagerTest(unittest.TestCase):
    """Tests for letsencrypt.plugins.standalone.ServerManager."""

    def setUp(self):
        from letsencrypt.plugins.standalone import ServerManager
        self.certs = {}
        self.simple_http_resources = {}
        self.mgr = ServerManager(self.certs, self.simple_http_resources)

    def test_init(self):
        self.assertTrue(self.mgr.certs is self.certs)
        self.assertTrue(
            self.mgr.simple_http_resources is self.simple_http_resources)

    def test_run_stop_non_tls(self):
        server, thread = self.mgr.run(port=0, tls=False)
        self.mgr.stop(port=server.socket.getsockname())

    def test_run_stop_tls(self):
        server, thread = self.mgr.run(port=0, tls=True)
        self.mgr.stop(port=server.socket.getsockname())

    def test_run_idempotent(self):
        server, thread = self.mgr.run(port=0, tls=False)
        port = server.socket.getsockname()
        server2, thread2 = self.mgr.run(port=port, tls=False)
        self.assertTrue(server is server2)
        self.assertTrue(thread2 is thread2)
        self.mgr.stop(port)

    def test_run_bind_error(self):
        some_server = socket.socket()
        some_server.bind(("", 0))
        port = some_server.getsockname()[1]
        self.assertRaises(
            errors.StandaloneBindError, self.mgr.run, port, tls=False)

    def test_items(self):
        server, thread = self.mgr.run(port=0, tls=True)
        port = server.socket.getsockname()
        self.assertEqual(port, self.mgr.items()[0][0])
        self.assertTrue(self.mgr.items()[0][1][0] is server)
        self.assertTrue(self.mgr.items()[0][1][1] is thread)
        self.mgr.stop(port=port)


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
