"""Tests for letsencrypt.cli."""
import itertools
import unittest

import mock

from letsencrypt import errors

class CLITest(unittest.TestCase):
    """Tests for different commands."""

    @classmethod
    def _call(cls, args):
        from letsencrypt import cli
        args = ['--text'] + args
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
            try:
                self._call(['plugins',] + list(args))
            except errors.ConfiguratorError as err:
                if "--prepare" not in args:
                    raise err


if __name__ == '__main__':
    unittest.main()  # pragma: no cover
