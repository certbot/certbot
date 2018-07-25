"""Test certbot.display.completer."""
import os
import readline
import string
import sys
import unittest

import mock
from six.moves import reload_module  # pylint: disable=import-error

from acme.magic_typing import List  # pylint: disable=unused-import, no-name-in-module
from certbot.tests.util import TempDirTestCase

class CompleterTest(TempDirTestCase):
    """Test certbot.display.completer.Completer."""

    def setUp(self):
        super(CompleterTest, self).setUp()

        # directories must end with os.sep for completer to
        # search inside the directory for possible completions
        if self.tempdir[-1] != os.sep:
            self.tempdir += os.sep

        self.paths = []  # type: List[str]
        # create some files and directories in temp_dir
        for c in string.ascii_lowercase:
            path = os.path.join(self.tempdir, c)
            self.paths.append(path)
            if ord(c) % 2:
                os.mkdir(path)
            else:
                with open(path, 'w'):
                    pass

    def test_complete(self):
        from certbot.display import completer
        my_completer = completer.Completer()
        num_paths = len(self.paths)

        for i in range(num_paths):
            completion = my_completer.complete(self.tempdir, i)
            self.assertTrue(completion in self.paths)
            self.paths.remove(completion)

        self.assertFalse(self.paths)
        completion = my_completer.complete(self.tempdir, num_paths)
        self.assertEqual(completion, None)

    def test_import_error(self):
        original_readline = sys.modules['readline']
        sys.modules['readline'] = None

        self.test_context_manager_with_unmocked_readline()

        sys.modules['readline'] = original_readline

    def test_context_manager_with_unmocked_readline(self):
        from certbot.display import completer
        reload_module(completer)

        original_completer = readline.get_completer()
        original_delims = readline.get_completer_delims()

        with completer.Completer():
            pass

        self.assertEqual(readline.get_completer(), original_completer)
        self.assertEqual(readline.get_completer_delims(), original_delims)

    @mock.patch('certbot.display.completer.readline', autospec=True)
    def test_context_manager_libedit(self, mock_readline):
        mock_readline.__doc__ = 'libedit'
        self._test_context_manager_with_mock_readline(mock_readline)

    @mock.patch('certbot.display.completer.readline', autospec=True)
    def test_context_manager_readline(self, mock_readline):
        mock_readline.__doc__ = 'GNU readline'
        self._test_context_manager_with_mock_readline(mock_readline)

    def _test_context_manager_with_mock_readline(self, mock_readline):
        from certbot.display import completer

        mock_readline.parse_and_bind.side_effect = enable_tab_completion

        with completer.Completer():
            pass

        self.assertTrue(mock_readline.parse_and_bind.called)


def enable_tab_completion(unused_command):
    """Enables readline tab completion using the system specific syntax."""
    libedit = 'libedit' in readline.__doc__
    command = 'bind ^I rl_complete' if libedit else 'tab: complete'
    readline.parse_and_bind(command)

if __name__ == "__main__":
    unittest.main()  # pragma: no cover
