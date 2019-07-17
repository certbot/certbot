"""Unit test for os module."""
import unittest

from certbot.compat import os


class OsTest(unittest.TestCase):
    """Unit tests for os module."""
    def test_forbidden_methods(self):
        for method in ['chmod', 'chown', 'open', 'mkdir', 'makedirs', 'rename', 'replace']:
            self.assertRaises(RuntimeError, getattr(os, method))


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
