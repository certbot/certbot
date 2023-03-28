"""Tests for certbot.compat.misc"""
import sys
from unittest import mock

import pytest

from certbot.compat import os


class ExecuteStatusTest:
    """Tests for certbot.compat.misc.execute_command_status."""

    @classmethod
    def _call(cls, *args, **kwargs):
        from certbot.compat.misc import execute_command_status
        return execute_command_status(*args, **kwargs)

    def _test_common(self, returncode, stdout, stderr):
        given_command = "foo"
        given_name = "foo-hook"
        with mock.patch("certbot.compat.misc.subprocess.run") as mock_run:
            mock_run.return_value.stdout = stdout
            mock_run.return_value.stderr = stderr
            mock_run.return_value.returncode = returncode
            with mock.patch("certbot.compat.misc.logger") as mock_logger:
                assert self._call(given_name, given_command) == (returncode, stderr, stdout)

        executed_command = mock_run.call_args[1].get(
            "args", mock_run.call_args[0][0])
        if os.name == 'nt':
            expected_command = ['powershell.exe', '-Command', given_command]
        else:
            expected_command = given_command
        assert executed_command == expected_command
        assert executed_command == expected_command

        mock_logger.info.assert_any_call("Running %s command: %s",
                                         given_name, given_command)

    def test_it(self):
        for returncode in range(0, 2):
            for stdout in ("", "Hello World!",):
                for stderr in ("", "Goodbye Cruel World!"):
                    self._test_common(returncode, stdout, stderr)


if __name__ == "__main__":
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover
