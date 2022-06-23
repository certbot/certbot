"""Tests for certbot.plugins.util."""
import unittest
from unittest import mock

from certbot.compat import os


class GetPrefixTest(unittest.TestCase):
    """Tests for certbot.plugins.get_prefixes."""
    def test_get_prefix(self):
        from certbot.plugins.util import get_prefixes
        self.assertEqual(
            get_prefixes('/a/b/c'),
            [os.path.normpath(path) for path in ['/a/b/c', '/a/b', '/a', '/']])
        self.assertEqual(get_prefixes('/'), [os.path.normpath('/')])
        self.assertEqual(get_prefixes('a'), ['a'])


class PathSurgeryTest(unittest.TestCase):
    """Tests for certbot.plugins.path_surgery."""

    @mock.patch("certbot.plugins.util.logger.debug")
    def test_path_surgery(self, mock_debug):
        from certbot.plugins.util import path_surgery
        all_path = {"PATH": "/usr/local/bin:/bin/:/usr/sbin/:/usr/local/sbin/"}
        with mock.patch.dict('os.environ', all_path):
            with mock.patch('certbot.util.exe_exists') as mock_exists:
                mock_exists.return_value = True
                self.assertIs(path_surgery("eg"), True)
                self.assertEqual(mock_debug.call_count, 0)
                self.assertEqual(os.environ["PATH"], all_path["PATH"])
        if os.name != 'nt':
            # This part is specific to Linux since on Windows no PATH surgery is ever done.
            no_path = {"PATH": "/tmp/"}
            with mock.patch.dict('os.environ', no_path):
                path_surgery("thingy")
                self.assertEqual(mock_debug.call_count, 2 if os.name != 'nt' else 1)
                self.assertIn("Failed to find", mock_debug.call_args[0][0])
                self.assertIn("/usr/local/bin", os.environ["PATH"])
                self.assertIn("/tmp", os.environ["PATH"])


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
