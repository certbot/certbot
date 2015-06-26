"""Tests for letsencrypt.cli."""
import itertools
import os
import shutil
import tempfile
import unittest

import mock


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


if __name__ == '__main__':
    unittest.main()  # pragma: no cover
