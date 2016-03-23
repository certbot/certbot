"""Test letsencrypt.display.completer."""
import os
import readline
import shutil
import string
import tempfile
import unittest


class CompleterTest(unittest.TestCase):
    """Test letsencrypt.display.completer.Completer."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

        # directories must end with os.sep for completer to
        # search inside the directory for possible completions
        if self.temp_dir[-1] != os.sep:
            self.temp_dir += os.sep

        self.paths = []
        # create some files and directories in temp_dir
        for c in string.ascii_lowercase:
            path = os.path.join(self.temp_dir, c)
            self.paths.append(path)
            if ord(c) % 2:
                os.mkdir(path)
            else:
                with open(path, 'w'):
                    pass

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def test_context_manager(self):
        from letsencrypt.display import completer

        original_completer = readline.get_completer()
        original_delims = readline.get_completer_delims()

        with completer.Completer():
            pass

        self.assertEqual(readline.get_completer(), original_completer)
        self.assertEqual(readline.get_completer_delims(), original_delims)

    def test_complete(self):
        from letsencrypt.display import completer

        my_completer = completer.Completer()
        num_paths = len(self.paths)

        for i in range(num_paths):
            completion = my_completer.complete(self.temp_dir, i)
            self.assertTrue(completion in self.paths)
            self.paths.remove(completion)

        self.assertFalse(self.paths)
        completion = my_completer.complete(self.temp_dir, num_paths)
        self.assertEqual(completion, None)


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
