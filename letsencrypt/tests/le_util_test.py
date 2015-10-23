"""Tests for letsencrypt.le_util."""
import errno
import os
import shutil
import stat
import tempfile
import unittest

import mock

from letsencrypt import errors


class RunScriptTest(unittest.TestCase):
    """Tests for letsencrypt.le_util.run_script."""
    @classmethod
    def _call(cls, params):
        from letsencrypt.le_util import run_script
        return run_script(params)

    @mock.patch("letsencrypt.le_util.subprocess.Popen")
    def test_default(self, mock_popen):
        """These will be changed soon enough with reload."""
        mock_popen().returncode = 0
        mock_popen().communicate.return_value = ("stdout", "stderr")

        out, err = self._call(["test"])
        self.assertEqual(out, "stdout")
        self.assertEqual(err, "stderr")

    @mock.patch("letsencrypt.le_util.subprocess.Popen")
    def test_bad_process(self, mock_popen):
        mock_popen.side_effect = OSError

        self.assertRaises(errors.SubprocessError, self._call, ["test"])

    @mock.patch("letsencrypt.le_util.subprocess.Popen")
    def test_failure(self, mock_popen):
        mock_popen().communicate.return_value = ("", "")
        mock_popen().returncode = 1

        self.assertRaises(errors.SubprocessError, self._call, ["test"])


class ExeExistsTest(unittest.TestCase):
    """Tests for letsencrypt.le_util.exe_exists."""

    @classmethod
    def _call(cls, exe):
        from letsencrypt.le_util import exe_exists
        return exe_exists(exe)

    @mock.patch("letsencrypt.le_util.os.path.isfile")
    @mock.patch("letsencrypt.le_util.os.access")
    def test_full_path(self, mock_access, mock_isfile):
        mock_access.return_value = True
        mock_isfile.return_value = True
        self.assertTrue(self._call("/path/to/exe"))

    @mock.patch("letsencrypt.le_util.os.path.isfile")
    @mock.patch("letsencrypt.le_util.os.access")
    def test_on_path(self, mock_access, mock_isfile):
        mock_access.return_value = True
        mock_isfile.return_value = True
        self.assertTrue(self._call("exe"))

    @mock.patch("letsencrypt.le_util.os.path.isfile")
    @mock.patch("letsencrypt.le_util.os.access")
    def test_not_found(self, mock_access, mock_isfile):
        mock_access.return_value = False
        mock_isfile.return_value = True
        self.assertFalse(self._call("exe"))


class MakeOrVerifyDirTest(unittest.TestCase):
    """Tests for letsencrypt.le_util.make_or_verify_dir.

    Note that it is not possible to test for a wrong directory owner,
    as this testing script would have to be run as root.

    """

    def setUp(self):
        self.root_path = tempfile.mkdtemp()
        self.path = os.path.join(self.root_path, "foo")
        os.mkdir(self.path, 0o400)

        self.uid = os.getuid()

    def tearDown(self):
        shutil.rmtree(self.root_path, ignore_errors=True)

    def _call(self, directory, mode):
        from letsencrypt.le_util import make_or_verify_dir
        return make_or_verify_dir(directory, mode, self.uid, strict=True)

    def test_creates_dir_when_missing(self):
        path = os.path.join(self.root_path, "bar")
        self._call(path, 0o650)
        self.assertTrue(os.path.isdir(path))
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o650)

    def test_existing_correct_mode_does_not_fail(self):
        self._call(self.path, 0o400)
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o400)

    def test_existing_wrong_mode_fails(self):
        self.assertRaises(errors.Error, self._call, self.path, 0o600)

    def test_reraises_os_error(self):
        with mock.patch.object(os, "makedirs") as makedirs:
            makedirs.side_effect = OSError()
            self.assertRaises(OSError, self._call, "bar", 12312312)


class CheckPermissionsTest(unittest.TestCase):
    """Tests for letsencrypt.le_util.check_permissions.

    Note that it is not possible to test for a wrong file owner,
    as this testing script would have to be run as root.

    """

    def setUp(self):
        _, self.path = tempfile.mkstemp()
        self.uid = os.getuid()

    def tearDown(self):
        os.remove(self.path)

    def _call(self, mode):
        from letsencrypt.le_util import check_permissions
        return check_permissions(self.path, mode, self.uid)

    def test_ok_mode(self):
        os.chmod(self.path, 0o600)
        self.assertTrue(self._call(0o600))

    def test_wrong_mode(self):
        os.chmod(self.path, 0o400)
        self.assertFalse(self._call(0o600))


class UniqueFileTest(unittest.TestCase):
    """Tests for letsencrypt.le_util.unique_file."""

    def setUp(self):
        self.root_path = tempfile.mkdtemp()
        self.default_name = os.path.join(self.root_path, "foo.txt")

    def tearDown(self):
        shutil.rmtree(self.root_path, ignore_errors=True)

    def _call(self, mode=0o600):
        from letsencrypt.le_util import unique_file
        return unique_file(self.default_name, mode)

    def test_returns_fd_for_writing(self):
        fd, name = self._call()
        fd.write("bar")
        fd.close()
        self.assertEqual(open(name).read(), "bar")

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
        self.assertTrue(basename1.endswith("foo.txt"))
        basename2 = os.path.basename(name2)
        self.assertTrue(basename2.endswith("foo.txt"))
        basename3 = os.path.basename(name3)
        self.assertTrue(basename3.endswith("foo.txt"))


class UniqueLineageNameTest(unittest.TestCase):
    """Tests for letsencrypt.le_util.unique_lineage_name."""

    def setUp(self):
        self.root_path = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.root_path, ignore_errors=True)

    def _call(self, filename, mode=0o777):
        from letsencrypt.le_util import unique_lineage_name
        return unique_lineage_name(self.root_path, filename, mode)

    def test_basic(self):
        f, path = self._call("wow")
        self.assertTrue(isinstance(f, file))
        self.assertEqual(os.path.join(self.root_path, "wow.conf"), path)

    def test_multiple(self):
        for _ in xrange(10):
            f, name = self._call("wow")
        self.assertTrue(isinstance(f, file))
        self.assertTrue(isinstance(name, str))
        self.assertTrue("wow-0009.conf" in name)

    @mock.patch("letsencrypt.le_util.os.fdopen")
    def test_failure(self, mock_fdopen):
        err = OSError("whoops")
        err.errno = errno.EIO
        mock_fdopen.side_effect = err
        self.assertRaises(OSError, self._call, "wow")

    @mock.patch("letsencrypt.le_util.os.fdopen")
    def test_subsequent_failure(self, mock_fdopen):
        self._call("wow")
        err = OSError("whoops")
        err.errno = errno.EIO
        mock_fdopen.side_effect = err
        self.assertRaises(OSError, self._call, "wow")


class SafelyRemoveTest(unittest.TestCase):
    """Tests for letsencrypt.le_util.safely_remove."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "foo")

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def _call(self):
        from letsencrypt.le_util import safely_remove
        return safely_remove(self.path)

    def test_exists(self):
        with open(self.path, "w"):
            pass  # just create the file
        self._call()
        self.assertFalse(os.path.exists(self.path))

    def test_missing(self):
        self._call()
        # no error, yay!
        self.assertFalse(os.path.exists(self.path))

    @mock.patch("letsencrypt.le_util.os.remove")
    def test_other_error_passthrough(self, mock_remove):
        mock_remove.side_effect = OSError
        self.assertRaises(OSError, self._call)


class SafeEmailTest(unittest.TestCase):
    """Test safe_email."""
    @classmethod
    def _call(cls, addr):
        from letsencrypt.le_util import safe_email
        return safe_email(addr)

    def test_valid_emails(self):
        addrs = [
            "letsencrypt@letsencrypt.org",
            "tbd.ade@gmail.com",
            "abc_def.jdk@hotmail.museum",
        ]
        for addr in addrs:
            self.assertTrue(self._call(addr), "%s failed." % addr)

    def test_invalid_emails(self):
        addrs = [
            "letsencrypt@letsencrypt..org",
            ".tbd.ade@gmail.com",
            "~/abc_def.jdk@hotmail.museum",
        ]
        for addr in addrs:
            self.assertFalse(self._call(addr), "%s failed." % addr)


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
