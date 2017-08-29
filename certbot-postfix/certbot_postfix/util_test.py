"""Tests for certbot_postfix.util."""

import subprocess
import unittest

import mock


class CheckCallTest(unittest.TestCase):
    """Tests for certbot_postfix.util.check_call."""

    @classmethod
    def _call(cls, *args, **kwargs):
        from certbot_postfix.util import check_call
        return check_call(*args, **kwargs)

    @mock.patch('certbot_postfix.util.logger')
    @mock.patch('certbot_postfix.util.subprocess.check_call')
    def test_failure(self, mock_check_call, mock_logger):
        cmd = "postconf smtpd_use_tls=yes".split()
        mock_check_call.side_effect = subprocess.CalledProcessError(42, cmd)
        self.assertRaises(subprocess.CalledProcessError, self._call, cmd)
        self.assertTrue(mock_logger.method_calls)

    @mock.patch('certbot_postfix.util.subprocess.check_call')
    def test_success(self, mock_check_call):
        cmd = "postconf smtpd_use_tls=yes".split()
        self._call(cmd)
        mock_check_call.assert_called_once_with(cmd)


class CheckOutputTest(unittest.TestCase):
    """Tests for certbot_postfix.util.check_output."""

    @classmethod
    def _call(cls, *args, **kwargs):
        from certbot_postfix.util import check_output
        return check_output(*args, **kwargs)

    @mock.patch('certbot_postfix.util.logger')
    @mock.patch('certbot_postfix.util.subprocess.Popen')
    def test_command_error(self, mock_popen, mock_logger):
        command = 'foo'
        retcode = 42
        output = 'bar'

        mock_popen().communicate.return_value = (output, '')
        mock_popen().poll.return_value = 42

        self.assertRaises(subprocess.CalledProcessError, self._call, command)

        log_args = mock_logger.debug.call_args[0]
        self.assertTrue(command in log_args)
        self.assertTrue(retcode in log_args)
        self.assertTrue(output in log_args)

    @mock.patch('certbot_postfix.util.subprocess.Popen')
    def test_success(self, mock_popen):
        command = 'foo'
        output = 'bar'
        mock_popen().communicate.return_value = (output, '')
        mock_popen().poll.return_value = 0

        self.assertEqual(self._call(command), output)

    def test_stdout_error(self):
        self.assertRaises(ValueError, self._call, stdout=None)

    def test_universal_newlines_error(self):
        self.assertRaises(ValueError, self._call, universal_newlines=False)


if __name__ == '__main__':  # pragma: no cover
    unittest.main()
