"""Tests for certbot.compat.misc"""
try:
    import mock
except ImportError:  # pragma: no cover
    from unittest import mock  # type: ignore
import unittest

from certbot.compat import os


class ExecuteTest(unittest.TestCase):
    """Tests for certbot.compat.misc.execute_command."""

    @classmethod
    def _call(cls, *args, **kwargs):
        from certbot.compat.misc import execute_command
        return execute_command(*args, **kwargs)

    def test_it(self):
        for returncode in range(0, 2):
            for stdout in ("", "Hello World!",):
                for stderr in ("", "Goodbye Cruel World!"):
                    self._test_common(returncode, stdout, stderr)

    def _test_common(self, returncode, stdout, stderr):
        given_command = "foo"
        given_name = "foo-hook"
        with mock.patch("certbot.compat.misc.subprocess.Popen") as mock_popen:
            mock_popen.return_value.communicate.return_value = (stdout, stderr)
            mock_popen.return_value.returncode = returncode
            with mock.patch("certbot.compat.misc.logger") as mock_logger:
                self.assertEqual(self._call(given_name, given_command), (stderr, stdout))

        executed_command = mock_popen.call_args[1].get(
            "args", mock_popen.call_args[0][0])
        if os.name == 'nt':
            expected_command = ['powershell.exe', '-Command', given_command]
        else:
            expected_command = given_command
        self.assertEqual(executed_command, expected_command)

        mock_logger.info.assert_any_call("Running %s command: %s",
                                         given_name, given_command)
        if stdout:
            mock_logger.info.assert_any_call(mock.ANY, mock.ANY,
                                             mock.ANY, stdout)
        if stderr or returncode:
            self.assertTrue(mock_logger.error.called)
