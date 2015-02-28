"""Tests for letsencrypt.client.le_util."""
import os
import shutil
import stat
import tempfile
import unittest

import mock

from letsencrypt.client import errors


class MakeOrVerifyDirTest(unittest.TestCase):
    """Tests for letsencrypt.client.le_util.make_or_verify_dir.

    Note that it is not possible to test for a wrong directory owner,
    as this testing script would have to be run as root.

    """

    def setUp(self):
        self.root_path = tempfile.mkdtemp()
        self.path = os.path.join(self.root_path, 'foo')
        os.mkdir(self.path, 0o400)

        self.uid = os.getuid()

    def tearDown(self):
        shutil.rmtree(self.root_path, ignore_errors=True)

    def _call(self, directory, mode):
        from letsencrypt.client.le_util import make_or_verify_dir
        return make_or_verify_dir(directory, mode, self.uid)

    def test_creates_dir_when_missing(self):
        path = os.path.join(self.root_path, 'bar')
        self._call(path, 0o650)
        self.assertTrue(os.path.isdir(path))
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o650)

    def test_existing_correct_mode_does_not_fail(self):
        self._call(self.path, 0o400)
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o400)

    def test_existing_wrong_mode_fails(self):
        self.assertRaises(errors.Error, self._call, self.path, 0o600)

    def test_reraises_os_error(self):
        with mock.patch.object(os, 'makedirs') as makedirs:
            makedirs.side_effect = OSError()
            self.assertRaises(OSError, self._call, 'bar', 12312312)


class CheckPermissionsTest(unittest.TestCase):
    """Tests for letsencrypt.client.le_util.check_permissions.

    Note that it is not possible to test for a wrong file owner,
    as this testing script would have to be run as root.

    """

    def setUp(self):
        _, self.path = tempfile.mkstemp()
        self.uid = os.getuid()

    def tearDown(self):
        os.remove(self.path)

    def _call(self, mode):
        from letsencrypt.client.le_util import check_permissions
        return check_permissions(self.path, mode, self.uid)

    def test_ok_mode(self):
        os.chmod(self.path, 0o600)
        self.assertTrue(self._call(0o600))

    def test_wrong_mode(self):
        os.chmod(self.path, 0o400)
        self.assertFalse(self._call(0o600))


class UniqueFileTest(unittest.TestCase):
    """Tests for letsencrypt.class.le_util.unique_file."""

    def setUp(self):
        self.root_path = tempfile.mkdtemp()
        self.default_name = os.path.join(self.root_path, 'foo.txt')

    def tearDown(self):
        shutil.rmtree(self.root_path, ignore_errors=True)

    def _call(self, mode=0o600):
        from letsencrypt.client.le_util import unique_file
        return unique_file(self.default_name, mode)

    def test_returns_fd_for_writing(self):
        fd, name = self._call()
        fd.write('bar')
        fd.close()
        self.assertEqual(open(name).read(), 'bar')

    def test_right_mode(self):
        self.assertEqual(0o700, os.stat(self._call(0o700)[1]).st_mode & 0o777)
        self.assertEqual(0o100, os.stat(self._call(0o100)[1]).st_mode & 0o777)

    def test_default_exists(self):
        name1 = self._call()[1]  # create 0000_foo.txt
        name2 = self._call()[1]
        name3 = self._call()[1]

        self.assertNotEqual(name1, name2)
        self.assertNotEqual(name1, name3)
        self.assertNotEqual(name2, name3)

        self.assertEqual(os.path.dirname(name1), self.root_path)
        self.assertEqual(os.path.dirname(name2), self.root_path)
        self.assertEqual(os.path.dirname(name3), self.root_path)

        basename1 = os.path.basename(name2)
        self.assertTrue(basename1.endswith('foo.txt'))
        basename2 = os.path.basename(name2)
        self.assertTrue(basename2.endswith('foo.txt'))
        basename3 = os.path.basename(name3)
        self.assertTrue(basename3.endswith('foo.txt'))


if __name__ == '__main__':
    unittest.main()
