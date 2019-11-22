"""Unit test for os module."""
import unittest

from certbot.compat import os


class OsTest(unittest.TestCase):
    """Unit tests for os module."""
    def test_forbidden_methods(self):
        # Checks for os module
        for method in ['chmod', 'chown', 'open', 'mkdir', 'makedirs', 'rename',
                       'replace', 'access', 'stat', 'fstat']:
            self.assertRaises(RuntimeError, getattr(os, method))
        # Checks for os.path module
        for method in ['realpath']:
            self.assertRaises(RuntimeError, getattr(os.path, method))


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
