"""Tests for letsencrypt.cli."""
import itertools
import unittest

import mock


class CLITest(unittest.TestCase):
    """Tests for different commands."""

    @classmethod
    def _call(cls, args):
        from letsencrypt import cli
        args = ['--text'] + args
        with mock.patch("letsencrypt.cli.sys.stdout") as stdout:
            with mock.patch("letsencrypt.cli.sys.stderr") as stderr:
                ret = cli.main(args)
        return ret, stdout, stderr

    def test_no_flags(self):
        self.assertRaises(SystemExit, self._call, [])

    def test_help(self):
        self.assertRaises(SystemExit, self._call, ['--help'])

    def test_plugins(self):
        flags = ['--init', '--prepare', '--authenticators', '--installers']
        for args in itertools.chain(
                *(itertools.combinations(flags, r)
                  for r in xrange(len(flags)))):
            self._call(['plugins',] + list(args))


if __name__ == '__main__':
    unittest.main()  # pragma: no cover
