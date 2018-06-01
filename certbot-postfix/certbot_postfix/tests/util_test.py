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

    @mock.patch('certbot_postfix.util.check_all_output')
    def test_call_extends_args(self, mock_output):
        # pylint: disable=protected-access
        with mock.patch('certbot_postfix.util.verify_exe_exists'):
            mock_output.return_value = 'expected'
            postfix = self._create_object('executable')
            postfix._call(['many', 'extra', 'args'])
            mock_output.assert_called_with(['executable', 'many', 'extra', 'args'])
            postfix._call()
            mock_output.assert_called_with(['executable'])

class PostfixUtilTest(unittest.TestCase):
    def setUp(self):
        # pylint: disable=protected-access
        from certbot_postfix.util import PostfixUtil
        with mock.patch('certbot_postfix.util.verify_exe_exists'):
            self.postfix = PostfixUtil()
            self.postfix._call = mock.Mock()
            self.mock_call = self.postfix._call

    def test_test(self):
        self.postfix.test()
        self.mock_call.assert_called_with(['check'])

    def test_test_raises_error_when_check_fails(self):
        self.mock_call.side_effect = [subprocess.CalledProcessError(None, None, None)]
        self.assertRaises(errors.MisconfigurationError, self.postfix.test)
        self.mock_call.assert_called_with(['check'])

    def test_restart_while_running(self):
        self.mock_call.side_effect = [subprocess.CalledProcessError(None, None, None), None]
        self.postfix.restart()
        self.mock_call.assert_called_with(['start'])

    def test_restart_while_not_running(self):
        self.postfix.restart()
        self.mock_call.assert_called_with(['reload'])

    def test_restart_raises_error_when_reload_fails(self):
        self.mock_call.side_effect = [None, subprocess.CalledProcessError(None, None, None)]
        self.assertRaises(errors.PluginError, self.postfix.restart)
        self.mock_call.assert_called_with(['reload'])

    def test_restart_raises_error_when_start_fails(self):
        self.mock_call.side_effect = [
             subprocess.CalledProcessError(None, None, None),
             subprocess.CalledProcessError(None, None, None)]
        self.assertRaises(errors.PluginError, self.postfix.restart)
        self.mock_call.assert_called_with(['start'])

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

class TestUtils(unittest.TestCase):
    """ Testing random utility functions in util.py
    """
    def test_report_master_overrides(self):
        from certbot_postfix.util import report_master_overrides
        self.assertRaises(errors.PluginError, report_master_overrides, 'name',
                          [('service/type', 'value')])
        # Shouldn't raise error
        report_master_overrides('name', [('service/type', 'value')],
                                acceptable_overrides='value')
        report_master_overrides('name', [('service/type', 'value')],
                                acceptable_overrides=('value', 'value1'))

    def test_is_acceptable_value(self):
        from certbot_postfix.util import is_acceptable_value
        self.assertTrue(is_acceptable_value('name', 'value', 'value'))
        self.assertFalse(is_acceptable_value('name', 'bad', 'value'))

    def test_is_acceptable_tuples(self):
        from certbot_postfix.util import is_acceptable_value
        self.assertTrue(is_acceptable_value('name', 'value', ('value', 'value1')))
        self.assertFalse(is_acceptable_value('name', 'bad', ('value', 'value1')))

    def test_is_acceptable_protocols(self):
        from certbot_postfix.util import is_acceptable_value
        # SSLv2 and SSLv3 are both not supported, unambiguously
        self.assertFalse(is_acceptable_value('tls_protocols_lol',
            'SSLv2, SSLv3', ''))
        self.assertFalse(is_acceptable_value('tls_protocols_lol',
            '!SSLv2, !TLSv1', ''))
        self.assertFalse(is_acceptable_value('tls_protocols_lol',
            '!SSLv2, SSLv3, !SSLv3, ', ''))
        self.assertTrue(is_acceptable_value('tls_protocols_lol',
            '!SSLv2, !SSLv3', ''))
        self.assertTrue(is_acceptable_value('tls_protocols_lol',
            '!SSLv3, !TLSv1, !SSLv2', ''))
        # TLSv1.2 is supported unambiguously
        self.assertFalse(is_acceptable_value('tls_protocols_lol',
            'TLSv1, TLSv1.1,', ''))
        self.assertFalse(is_acceptable_value('tls_protocols_lol',
            'TLSv1.2, !TLSv1.2,', ''))
        self.assertTrue(is_acceptable_value('tls_protocols_lol',
            'TLSv1.2, ', ''))
        self.assertTrue(is_acceptable_value('tls_protocols_lol',
            'TLSv1, TLSv1.1, TLSv1.2', ''))

if __name__ == '__main__': # pragma: no cover
    unittest.main()
