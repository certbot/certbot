"""Test certbot._internal.display.completer."""
from typing import List

try:
    import readline  # pylint: disable=import-error
except ImportError:
    import certbot._internal.display.dummy_readline as readline  # type: ignore
from importlib import reload as reload_module
import string
import sys
import unittest

from certbot.compat import filesystem
from certbot.compat import os
import certbot.tests.util as test_util

try:
    import mock
except ImportError: # pragma: no cover
    from unittest import mock



class CompleterTest(test_util.TempDirTestCase):
    """Test certbot._internal.display.completer.Completer."""

    def setUp(self):
        super().setUp()

        # directories must end with os.sep for completer to
        # search inside the directory for possible completions
        if self.tempdir[-1] != os.sep:
            self.tempdir += os.sep

        self.paths: List[str] = []
        # create some files and directories in temp_dir
        for c in string.ascii_lowercase:
            path = os.path.join(self.tempdir, c)
            self.paths.append(path)
            if ord(c) % 2:
                filesystem.mkdir(path)
            else:
                with open(path, 'w'):
                    pass

    def test_complete(self):
        from certbot._internal.display import completer
        my_completer = completer.Completer()
        num_paths = len(self.paths)

        for i in range(num_paths):
            completion = my_completer.complete(self.tempdir, i)
            self.assertIn(completion, self.paths)
            self.paths.remove(completion)

        self.assertEqual(len(self.paths), 0)
        completion = my_completer.complete(self.tempdir, num_paths)
        self.assertIsNone(completion)

    @unittest.skipIf('readline' not in sys.modules,
                     reason='Not relevant if readline is not available.')
    def test_import_error(self):
        original_readline = sys.modules['readline']
        sys.modules['readline'] = None

        self.test_context_manager_with_unmocked_readline()

        sys.modules['readline'] = original_readline

    def test_context_manager_with_unmocked_readline(self):
        from certbot._internal.display import completer
        reload_module(completer)

        original_completer = readline.get_completer()
        original_delims = readline.get_completer_delims()

        with completer.Completer():
            pass

        self.assertEqual(readline.get_completer(), original_completer)
        self.assertEqual(readline.get_completer_delims(), original_delims)

    @mock.patch('certbot._internal.display.completer.readline', autospec=True)
    def test_context_manager_libedit(self, mock_readline):
        mock_readline.__doc__ = 'libedit'
        self._test_context_manager_with_mock_readline(mock_readline)

    @mock.patch('certbot._internal.display.completer.readline', autospec=True)
    def test_context_manager_readline(self, mock_readline):
        mock_readline.__doc__ = 'GNU readline'
        self._test_context_manager_with_mock_readline(mock_readline)

    def _test_context_manager_with_mock_readline(self, mock_readline):
        from certbot._internal.display import completer

        mock_readline.parse_and_bind.side_effect = enable_tab_completion

        with completer.Completer():
            pass

        self.assertIs(mock_readline.parse_and_bind.called, True)


def enable_tab_completion(unused_command):
    """Enables readline tab completion using the system specific syntax."""
    libedit = readline.__doc__ is not None and 'libedit' in readline.__doc__
    command = 'bind ^I rl_complete' if libedit else 'tab: complete'
    readline.parse_and_bind(command)


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
