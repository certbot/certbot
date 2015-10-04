"""Tests for letsencrypt.plugins.standalone."""
import unittest


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


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
