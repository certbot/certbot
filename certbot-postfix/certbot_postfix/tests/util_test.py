"""Tests for certbot_postfix.util."""

import subprocess
import unittest

import mock

from certbot import errors


class PostfixUtilBaseTest(unittest.TestCase):
    """Tests for certbot_postfix.util.PostfixUtilBase."""

    @classmethod
    def _create_object(cls, *args, **kwargs):
        from certbot_postfix.util import PostfixUtilBase
        return PostfixUtilBase(*args, **kwargs)

    @mock.patch('certbot_postfix.util.verify_exe_exists')
    def test_no_exe(self, mock_verify):
        expected_error = errors.NoInstallationError
        mock_verify.side_effect = expected_error
        self.assertRaises(expected_error, self._create_object, 'nonexistent')

    def test_object_creation(self):
        with mock.patch('certbot_postfix.util.verify_exe_exists'):
            self._create_object('existent')


class CheckAllOutputTest(unittest.TestCase):
    """Tests for certbot_postfix.util.check_all_output."""

    @classmethod
    def _call(cls, *args, **kwargs):
        from certbot_postfix.util import check_all_output
        return check_all_output(*args, **kwargs)

    @mock.patch('certbot_postfix.util.logger')
    @mock.patch('certbot_postfix.util.subprocess.Popen')
    def test_command_error(self, mock_popen, mock_logger):
        command = 'foo'
        retcode = 42
        output = 'bar'
        err = 'baz'

        mock_popen().communicate.return_value = (output, err)
        mock_popen().poll.return_value = 42

        self.assertRaises(subprocess.CalledProcessError, self._call, command)
        log_args = mock_logger.debug.call_args[0]
        for value in (command, retcode, output, err,):
            self.assertTrue(value in log_args)

    @mock.patch('certbot_postfix.util.subprocess.Popen')
    def test_success(self, mock_popen):
        command = 'foo'
        expected = ('bar', '')
        mock_popen().communicate.return_value = expected
        mock_popen().poll.return_value = 0

        self.assertEqual(self._call(command), expected)

    def test_stdout_error(self):
        self.assertRaises(ValueError, self._call, stdout=None)

    def test_stderr_error(self):
        self.assertRaises(ValueError, self._call, stderr=None)

    def test_universal_newlines_error(self):
        self.assertRaises(ValueError, self._call, universal_newlines=False)


class VerifyExeExistsTest(unittest.TestCase):
    """Tests for certbot_postfix.util.verify_exe_exists."""

    @classmethod
    def _call(cls, *args, **kwargs):
        from certbot_postfix.util import verify_exe_exists
        return verify_exe_exists(*args, **kwargs)

    @mock.patch('certbot_postfix.util.certbot_util.exe_exists')
    @mock.patch('certbot_postfix.util.plugins_util.path_surgery')
    def test_failure(self, mock_exe_exists, mock_path_surgery):
        mock_exe_exists.return_value = mock_path_surgery.return_value = False
        self.assertRaises(errors.NoInstallationError, self._call, 'foo')

    @mock.patch('certbot_postfix.util.certbot_util.exe_exists')
    def test_simple_success(self, mock_exe_exists):
        mock_exe_exists.return_value = True
        self._call('foo')

    @mock.patch('certbot_postfix.util.certbot_util.exe_exists')
    @mock.patch('certbot_postfix.util.plugins_util.path_surgery')
    def test_successful_surgery(self, mock_exe_exists, mock_path_surgery):
        mock_exe_exists.return_value = False
        mock_path_surgery.return_value = True
        self._call('foo')

if __name__ == '__main__':  # pragma: no cover
    unittest.main()
