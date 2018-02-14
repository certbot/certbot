"""Tests for certbot.plugins.util."""
import os
import unittest

import mock


class PathSurgeryTest(unittest.TestCase):
    """Tests for certbot.plugins.path_surgery."""

    @mock.patch("certbot.plugins.util.logger.warning")
    @mock.patch("certbot.plugins.util.logger.debug")
    def test_path_surgery(self, mock_debug, mock_warn):
        from certbot.plugins.util import path_surgery
        all_path = {"PATH": "/usr/local/bin:/bin/:/usr/sbin/:/usr/local/sbin/"}
        with mock.patch.dict('os.environ', all_path):
            with mock.patch('certbot.util.exe_exists') as mock_exists:
                mock_exists.return_value = True
                self.assertEqual(path_surgery("eg"), True)
                self.assertEqual(mock_debug.call_count, 0)
                self.assertEqual(mock_warn.call_count, 0)
                self.assertEqual(os.environ["PATH"], all_path["PATH"])
        no_path = {"PATH": "/tmp/"}
        with mock.patch.dict('os.environ', no_path):
            path_surgery("thingy")
            self.assertEqual(mock_debug.call_count, 1)
            self.assertEqual(mock_warn.call_count, 1)
            self.assertTrue("Failed to find" in mock_warn.call_args[0][0])
            self.assertTrue("/usr/local/bin" in os.environ["PATH"])
            self.assertTrue("/tmp" in os.environ["PATH"])


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
