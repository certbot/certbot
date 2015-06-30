"""Tests for letsencrypt.cli."""
import itertools
import os
import shutil
import traceback
import tempfile
import unittest

import mock

from letsencrypt import errors


class CLITest(unittest.TestCase):
    """Tests for different commands."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.config_dir = os.path.join(self.tmp_dir, 'config')
        self.work_dir = os.path.join(self.tmp_dir, 'work')
        self.logs_dir = os.path.join(self.tmp_dir, 'logs')

    def tearDown(self):
        shutil.rmtree(self.tmp_dir)

    def _call(self, args):
        from letsencrypt import cli
        args = ['--text', '--config-dir', self.config_dir,
                '--work-dir', self.work_dir, '--logs-dir', self.logs_dir] + args
        with mock.patch('letsencrypt.cli.sys.stdout') as stdout:
            with mock.patch('letsencrypt.cli.sys.stderr') as stderr:
                with mock.patch('letsencrypt.cli.client') as client:
                    ret = cli.main(args)
        return ret, stdout, stderr, client

    def test_no_flags(self):
        self.assertRaises(SystemExit, self._call, [])

    def test_help(self):
        self.assertRaises(SystemExit, self._call, ['--help'])
        self.assertRaises(SystemExit, self._call, ['--help all'])

    def test_rollback(self):
        _, _, _, client = self._call(['rollback'])
        client.rollback.assert_called_once()

        _, _, _, client = self._call(['rollback', '--checkpoints', '123'])
        client.rollback.assert_called_once_with(
            mock.ANY, 123, mock.ANY, mock.ANY)

    def test_config_changes(self):
        _, _, _, client = self._call(['config_changes'])
        client.view_config_changes.assert_called_once()

    def test_plugins(self):
        flags = ['--init', '--prepare', '--authenticators', '--installers']
        for args in itertools.chain(
                *(itertools.combinations(flags, r)
                  for r in xrange(len(flags)))):
            self._call(['plugins',] + list(args))

    @mock.patch("letsencrypt.cli.sys")
    def test_handle_exception(self, mock_sys):
        # pylint: disable=protected-access
        from letsencrypt import cli

        mock_open = mock.mock_open()
        with mock.patch("letsencrypt.cli.open", mock_open, create=True):
            exception = Exception("detail")
            cli._handle_exception(
                Exception, exc_value=exception, trace=None, args=None)
            mock_open().write.assert_called_once_with("".join(
                traceback.format_exception_only(Exception, exception)))
            error_msg = mock_sys.exit.call_args_list[0][0][0]
            self.assertTrue("unexpected error" in error_msg)

        with mock.patch("letsencrypt.cli.open", mock_open, create=True):
            mock_open.side_effect = [KeyboardInterrupt]
            error = errors.Error("detail")
            cli._handle_exception(
                errors.Error, exc_value=error, trace=None, args=None)
            # assert_any_call used because sys.exit doesn't exit in cli.py
            mock_sys.exit.assert_any_call("".join(
                traceback.format_exception_only(errors.Error, error)))

        args = mock.MagicMock(debug=False)
        cli._handle_exception(
            Exception, exc_value=Exception("detail"), trace=None, args=args)
        error_msg = mock_sys.exit.call_args_list[-1][0][0]
        self.assertTrue("unexpected error" in error_msg)

        interrupt = KeyboardInterrupt("detail")
        cli._handle_exception(
            KeyboardInterrupt, exc_value=interrupt, trace=None, args=None)
        mock_sys.exit.assert_called_with("".join(
            traceback.format_exception_only(KeyboardInterrupt, interrupt)))


if __name__ == '__main__':
    unittest.main()  # pragma: no cover
