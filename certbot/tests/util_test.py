"""Tests for certbot.util."""
import argparse
import errno
import os
import shutil
import stat
import tempfile
import unittest

import mock
import six

from certbot import errors
from certbot.tests import test_util


class RunScriptTest(unittest.TestCase):
    """Tests for certbot.util.run_script."""
    @classmethod
    def _call(cls, params):
        from certbot.util import run_script
        return run_script(params)

    @mock.patch("certbot.util.subprocess.Popen")
    def test_default(self, mock_popen):
        """These will be changed soon enough with reload."""
        mock_popen().returncode = 0
        mock_popen().communicate.return_value = ("stdout", "stderr")

        out, err = self._call(["test"])
        self.assertEqual(out, "stdout")
        self.assertEqual(err, "stderr")

    @mock.patch("certbot.util.subprocess.Popen")
    def test_bad_process(self, mock_popen):
        mock_popen.side_effect = OSError

        self.assertRaises(errors.SubprocessError, self._call, ["test"])

    @mock.patch("certbot.util.subprocess.Popen")
    def test_failure(self, mock_popen):
        mock_popen().communicate.return_value = ("", "")
        mock_popen().returncode = 1

        self.assertRaises(errors.SubprocessError, self._call, ["test"])


class ExeExistsTest(unittest.TestCase):
    """Tests for certbot.util.exe_exists."""

    @classmethod
    def _call(cls, exe):
        from certbot.util import exe_exists
        return exe_exists(exe)

    @mock.patch("certbot.util.os.path.isfile")
    @mock.patch("certbot.util.os.access")
    def test_full_path(self, mock_access, mock_isfile):
        mock_access.return_value = True
        mock_isfile.return_value = True
        self.assertTrue(self._call("/path/to/exe"))

    @mock.patch("certbot.util.os.path.isfile")
    @mock.patch("certbot.util.os.access")
    def test_on_path(self, mock_access, mock_isfile):
        mock_access.return_value = True
        mock_isfile.return_value = True
        self.assertTrue(self._call("exe"))

    @mock.patch("certbot.util.os.path.isfile")
    @mock.patch("certbot.util.os.access")
    def test_not_found(self, mock_access, mock_isfile):
        mock_access.return_value = False
        mock_isfile.return_value = True
        self.assertFalse(self._call("exe"))


class MakeOrVerifyDirTest(unittest.TestCase):
    """Tests for certbot.util.make_or_verify_dir.

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
        from certbot.util import make_or_verify_dir
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
    """Tests for certbot.util.check_permissions.

    Note that it is not possible to test for a wrong file owner,
    as this testing script would have to be run as root.

    """

    def setUp(self):
        _, self.path = tempfile.mkstemp()
        self.uid = os.getuid()

    def tearDown(self):
        os.remove(self.path)

    def _call(self, mode):
        from certbot.util import check_permissions
        return check_permissions(self.path, mode, self.uid)

    def test_ok_mode(self):
        os.chmod(self.path, 0o600)
        self.assertTrue(self._call(0o600))

    def test_wrong_mode(self):
        os.chmod(self.path, 0o400)
        self.assertFalse(self._call(0o600))


class UniqueFileTest(unittest.TestCase):
    """Tests for certbot.util.unique_file."""

    def setUp(self):
        self.root_path = tempfile.mkdtemp()
        self.default_name = os.path.join(self.root_path, "foo.txt")

    def tearDown(self):
        shutil.rmtree(self.root_path, ignore_errors=True)

    def _call(self, mode=0o600):
        from certbot.util import unique_file
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


try:
    file_type = file
except NameError:
    import io
    file_type = io.TextIOWrapper

class UniqueLineageNameTest(unittest.TestCase):
    """Tests for certbot.util.unique_lineage_name."""

    def setUp(self):
        self.root_path = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.root_path, ignore_errors=True)

    def _call(self, filename, mode=0o777):
        from certbot.util import unique_lineage_name
        return unique_lineage_name(self.root_path, filename, mode)

    def test_basic(self):
        f, path = self._call("wow")
        self.assertTrue(isinstance(f, file_type))
        self.assertEqual(os.path.join(self.root_path, "wow.conf"), path)

    def test_multiple(self):
        for _ in six.moves.range(10):
            f, name = self._call("wow")
        self.assertTrue(isinstance(f, file_type))
        self.assertTrue(isinstance(name, str))
        self.assertTrue("wow-0009.conf" in name)

    @mock.patch("certbot.util.os.fdopen")
    def test_failure(self, mock_fdopen):
        err = OSError("whoops")
        err.errno = errno.EIO
        mock_fdopen.side_effect = err
        self.assertRaises(OSError, self._call, "wow")

    @mock.patch("certbot.util.os.fdopen")
    def test_subsequent_failure(self, mock_fdopen):
        self._call("wow")
        err = OSError("whoops")
        err.errno = errno.EIO
        mock_fdopen.side_effect = err
        self.assertRaises(OSError, self._call, "wow")


class SafelyRemoveTest(unittest.TestCase):
    """Tests for certbot.util.safely_remove."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "foo")

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def _call(self):
        from certbot.util import safely_remove
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

    @mock.patch("certbot.util.os.remove")
    def test_other_error_passthrough(self, mock_remove):
        mock_remove.side_effect = OSError
        self.assertRaises(OSError, self._call)


class SafeEmailTest(unittest.TestCase):
    """Test safe_email."""
    @classmethod
    def _call(cls, addr):
        from certbot.util import safe_email
        return safe_email(addr)

    def test_valid_emails(self):
        addrs = [
            "certbot@certbot.org",
            "tbd.ade@gmail.com",
            "abc_def.jdk@hotmail.museum",
        ]
        for addr in addrs:
            self.assertTrue(self._call(addr), "%s failed." % addr)

    def test_invalid_emails(self):
        addrs = [
            "certbot@certbot..org",
            ".tbd.ade@gmail.com",
            "~/abc_def.jdk@hotmail.museum",
        ]
        for addr in addrs:
            self.assertFalse(self._call(addr), "%s failed." % addr)


class AddDeprecatedArgumentTest(unittest.TestCase):
    """Test add_deprecated_argument."""
    def setUp(self):
        self.parser = argparse.ArgumentParser()

    def _call(self, argument_name, nargs):
        from certbot.util import add_deprecated_argument

        add_deprecated_argument(self.parser.add_argument, argument_name, nargs)

    def test_warning_no_arg(self):
        self._call("--old-option", 0)
        stderr = self._get_argparse_warnings(["--old-option"])
        self.assertTrue("--old-option is deprecated" in stderr)

    def test_warning_with_arg(self):
        self._call("--old-option", 1)
        stderr = self._get_argparse_warnings(["--old-option", "42"])
        self.assertTrue("--old-option is deprecated" in stderr)

    def _get_argparse_warnings(self, args):
        stderr = six.StringIO()
        with mock.patch("certbot.util.sys.stderr", new=stderr):
            self.parser.parse_args(args)
        return stderr.getvalue()

    def test_help(self):
        self._call("--old-option", 2)
        stdout = six.StringIO()
        with mock.patch("certbot.util.sys.stdout", new=stdout):
            try:
                self.parser.parse_args(["-h"])
            except SystemExit:
                pass
        self.assertTrue("--old-option" not in stdout.getvalue())


class EnforceLeValidity(unittest.TestCase):
    """Test enforce_le_validity."""
    def _call(self, domain):
        from certbot.util import enforce_le_validity
        return enforce_le_validity(domain)

    def test_sanity(self):
        self.assertRaises(errors.ConfigurationError, self._call, u"..")

    def test_invalid_chars(self):
        self.assertRaises(
            errors.ConfigurationError, self._call, u"hello_world.example.com")

    def test_leading_hyphen(self):
        self.assertRaises(
            errors.ConfigurationError, self._call, u"-a.example.com")

    def test_trailing_hyphen(self):
        self.assertRaises(
            errors.ConfigurationError, self._call, u"a-.example.com")

    def test_one_label(self):
        self.assertRaises(errors.ConfigurationError, self._call, u"com")

    def test_valid_domain(self):
        self.assertEqual(self._call(u"example.com"), u"example.com")


class EnforceDomainSanityTest(unittest.TestCase):
    """Test enforce_domain_sanity."""

    def _call(self, domain):
        from certbot.util import enforce_domain_sanity
        return enforce_domain_sanity(domain)

    def test_nonascii_str(self):
        self.assertRaises(errors.ConfigurationError, self._call,
                          u"eichh\u00f6rnchen.example.com".encode("utf-8"))

    def test_nonascii_unicode(self):
        self.assertRaises(errors.ConfigurationError, self._call,
                          u"eichh\u00f6rnchen.example.com")


class OsInfoTest(unittest.TestCase):
    """Test OS / distribution detection"""

    def test_systemd_os_release(self):
        from certbot.util import (get_os_info, get_systemd_os_info,
                                     get_os_info_ua)

        with mock.patch('os.path.isfile', return_value=True):
            self.assertEqual(get_os_info(
                test_util.vector_path("os-release"))[0], 'systemdos')
            self.assertEqual(get_os_info(
                test_util.vector_path("os-release"))[1], '42')
            self.assertEqual(get_systemd_os_info("/dev/null"), ("", ""))
            self.assertEqual(get_os_info_ua(
                test_util.vector_path("os-release")),
                "SystemdOS")
        with mock.patch('os.path.isfile', return_value=False):
            self.assertEqual(get_systemd_os_info(), ("", ""))

    def test_systemd_os_release_like(self):
        from certbot.util import get_systemd_os_like

        with mock.patch('os.path.isfile', return_value=True):
            id_likes = get_systemd_os_like(test_util.vector_path(
                "os-release"))
            self.assertEqual(len(id_likes), 3)
            self.assertTrue("debian" in id_likes)

    @mock.patch("certbot.util.subprocess.Popen")
    def test_non_systemd_os_info(self, popen_mock):
        from certbot.util import (get_os_info, get_python_os_info,
                                     get_os_info_ua)
        with mock.patch('os.path.isfile', return_value=False):
            with mock.patch('platform.system_alias',
                            return_value=('NonSystemD', '42', '42')):
                self.assertEqual(get_os_info()[0], 'nonsystemd')
                self.assertEqual(get_os_info_ua(),
                                 " ".join(get_python_os_info()))

            with mock.patch('platform.system_alias',
                            return_value=('darwin', '', '')):
                comm_mock = mock.Mock()
                comm_attrs = {'communicate.return_value':
                              ('42.42.42', 'error')}
                comm_mock.configure_mock(**comm_attrs)  # pylint: disable=star-args
                popen_mock.return_value = comm_mock
                self.assertEqual(get_os_info()[0], 'darwin')
                self.assertEqual(get_os_info()[1], '42.42.42')

            with mock.patch('platform.system_alias',
                            return_value=('linux', '', '')):
                with mock.patch('platform.linux_distribution',
                                return_value=('', '', '')):
                    self.assertEqual(get_python_os_info(), ("linux", ""))

                with mock.patch('platform.linux_distribution',
                                return_value=('testdist', '42', '')):
                    self.assertEqual(get_python_os_info(), ("testdist", "42"))

            with mock.patch('platform.system_alias',
                            return_value=('freebsd', '9.3-RC3-p1', '')):
                self.assertEqual(get_python_os_info(), ("freebsd", "9"))

            with mock.patch('platform.system_alias',
                            return_value=('windows', '', '')):
                with mock.patch('platform.win32_ver',
                                return_value=('4242', '95', '2', '')):
                    self.assertEqual(get_python_os_info(),
                                     ("windows", "95"))


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
