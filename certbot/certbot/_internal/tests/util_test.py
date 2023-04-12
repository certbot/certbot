"""Tests for certbot.util."""
import argparse
import errno
from importlib import reload as reload_module
import io
import sys
import unittest
from unittest import mock
import warnings

import pytest

from certbot import errors
from certbot.compat import filesystem
from certbot.compat import os
import certbot.tests.util as test_util


class EnvNoSnapForExternalCallsTest(unittest.TestCase):
    """Tests for certbot.util.env_no_snap_for_external_calls."""
    @classmethod
    def _call(cls):
        from certbot.util import env_no_snap_for_external_calls
        return env_no_snap_for_external_calls()

    def test_removed(self):
        original_path = os.environ['PATH']
        env_copy_dict = os.environ.copy()
        env_copy_dict['PATH'] = 'RANDOM_NONSENSE_GARBAGE/blah/blah:' + original_path
        env_copy_dict['SNAP'] = 'RANDOM_NONSENSE_GARBAGE'
        env_copy_dict['CERTBOT_SNAPPED'] = 'True'
        with mock.patch('certbot.compat.os.environ.copy', return_value=env_copy_dict):
            assert self._call()['PATH'] == original_path

    def test_noop(self):
        env_copy_dict_unmodified = os.environ.copy()
        env_copy_dict_unmodified['PATH'] = 'RANDOM_NONSENSE_GARBAGE/blah/blah:' \
            + env_copy_dict_unmodified['PATH']
        env_copy_dict = env_copy_dict_unmodified.copy()
        with mock.patch('certbot.compat.os.environ.copy', return_value=env_copy_dict):
            # contains neither necessary key
            env_copy_dict.pop('SNAP', None)
            env_copy_dict.pop('CERTBOT_SNAPPED', None)
            assert self._call()['PATH'] == env_copy_dict_unmodified['PATH']
            # contains only one necessary key
            env_copy_dict['SNAP'] = 'RANDOM_NONSENSE_GARBAGE'
            assert self._call()['PATH'] == env_copy_dict_unmodified['PATH']
            del env_copy_dict['SNAP']
            env_copy_dict['CERTBOT_SNAPPED'] = 'True'
            assert self._call()['PATH'] == env_copy_dict_unmodified['PATH']


class RunScriptTest(unittest.TestCase):
    """Tests for certbot.util.run_script."""
    @classmethod
    def _call(cls, params):
        from certbot.util import run_script
        return run_script(params)

    @mock.patch("certbot.util.subprocess.run")
    def test_default(self, mock_run):
        """These will be changed soon enough with reload."""
        mock_run().returncode = 0
        mock_run().stdout = "stdout"
        mock_run().stderr = "stderr"

        out, err = self._call(["test"])
        assert out == "stdout"
        assert err == "stderr"

    @mock.patch("certbot.util.subprocess.run")
    def test_bad_process(self, mock_run):
        mock_run.side_effect = OSError

        with pytest.raises(errors.SubprocessError):
            self._call(["test"])

    @mock.patch("certbot.util.subprocess.run")
    def test_failure(self, mock_run):
        mock_run().returncode = 1

        with pytest.raises(errors.SubprocessError):
            self._call(["test"])


class ExeExistsTest(unittest.TestCase):
    """Tests for certbot.util.exe_exists."""

    @classmethod
    def _call(cls, exe):
        from certbot.util import exe_exists
        return exe_exists(exe)

    def test_exe_exists(self):
        with mock.patch("certbot.util.filesystem.is_executable", return_value=True):
            assert self._call("/path/to/exe")

    def test_exe_not_exists(self):
        with mock.patch("certbot.util.filesystem.is_executable", return_value=False):
            assert not self._call("/path/to/exe")


class LockDirUntilExit(test_util.TempDirTestCase):
    """Tests for certbot.util.lock_dir_until_exit."""
    @classmethod
    def _call(cls, *args, **kwargs):
        from certbot.util import lock_dir_until_exit
        return lock_dir_until_exit(*args, **kwargs)

    def setUp(self):
        super().setUp()
        # reset global state from other tests
        import certbot.util
        reload_module(certbot.util)

    @mock.patch('certbot.util.logger')
    @mock.patch('certbot.util.atexit_register')
    def test_it(self, mock_register, mock_logger):
        subdir = os.path.join(self.tempdir, 'subdir')
        filesystem.mkdir(subdir)
        self._call(self.tempdir)
        self._call(subdir)
        self._call(subdir)

        assert mock_register.call_count == 1
        registered_func = mock_register.call_args[0][0]

        from certbot import util

        # Despite lock_dir_until_exit has been called twice to subdir, its lock should have been
        # added only once. So we expect to have two lock references: for self.tempdir and subdir
        assert len(util._LOCKS) == 2  # pylint: disable=protected-access
        registered_func()  # Exception should not be raised
        # Logically, logger.debug, that would be invoked in case of unlock failure,
        # should never been called.
        assert mock_logger.debug.call_count == 0


class SetUpCoreDirTest(test_util.TempDirTestCase):
    """Tests for certbot.util.make_or_verify_core_dir."""

    def _call(self, *args, **kwargs):
        from certbot.util import set_up_core_dir
        return set_up_core_dir(*args, **kwargs)

    @mock.patch('certbot.util.lock_dir_until_exit')
    def test_success(self, mock_lock):
        new_dir = os.path.join(self.tempdir, 'new')
        self._call(new_dir, 0o700, False)
        assert os.path.exists(new_dir)
        assert mock_lock.call_count == 1

    @mock.patch('certbot.util.make_or_verify_dir')
    def test_failure(self, mock_make_or_verify):
        mock_make_or_verify.side_effect = OSError
        with pytest.raises(errors.Error):
            self._call(self.tempdir, 0o700, False)


class MakeOrVerifyDirTest(test_util.TempDirTestCase):
    """Tests for certbot.util.make_or_verify_dir.

    Note that it is not possible to test for a wrong directory owner,
    as this testing script would have to be run as root.

    """

    def setUp(self):
        super().setUp()

        self.path = os.path.join(self.tempdir, "foo")
        filesystem.mkdir(self.path, 0o600)

    def _call(self, directory, mode):
        from certbot.util import make_or_verify_dir
        return make_or_verify_dir(directory, mode, strict=True)

    def test_creates_dir_when_missing(self):
        path = os.path.join(self.tempdir, "bar")
        self._call(path, 0o650)
        assert os.path.isdir(path)
        assert filesystem.check_mode(path, 0o650)

    def test_existing_correct_mode_does_not_fail(self):
        self._call(self.path, 0o600)
        assert filesystem.check_mode(self.path, 0o600)

    def test_existing_wrong_mode_fails(self):
        with pytest.raises(errors.Error):
            self._call(self.path, 0o400)

    def test_reraises_os_error(self):
        with mock.patch.object(filesystem, "makedirs") as makedirs:
            makedirs.side_effect = OSError()
            with pytest.raises(OSError):
                self._call("bar", 12312312)


class UniqueFileTest(test_util.TempDirTestCase):
    """Tests for certbot.util.unique_file."""

    def setUp(self):
        super().setUp()

        self.default_name = os.path.join(self.tempdir, "foo.txt")

    def _call(self, mode=0o600):
        from certbot.util import unique_file
        return unique_file(self.default_name, mode)

    def test_returns_fd_for_writing(self):
        fd, name = self._call()
        fd.write("bar")
        fd.close()
        with open(name) as f:
            assert f.read() == "bar"

    def test_right_mode(self):
        fd1, name1 = self._call(0o700)
        fd2, name2 = self._call(0o600)
        assert filesystem.check_mode(name1, 0o700)
        assert filesystem.check_mode(name2, 0o600)
        fd1.close()
        fd2.close()

    def test_default_exists(self):
        fd1, name1 = self._call()  # create 0000_foo.txt
        fd2, name2 = self._call()
        fd3, name3 = self._call()

        assert name1 != name2
        assert name1 != name3
        assert name2 != name3

        assert os.path.dirname(name1) == self.tempdir
        assert os.path.dirname(name2) == self.tempdir
        assert os.path.dirname(name3) == self.tempdir

        basename1 = os.path.basename(name2)
        assert basename1.endswith("foo.txt")
        basename2 = os.path.basename(name2)
        assert basename2.endswith("foo.txt")
        basename3 = os.path.basename(name3)
        assert basename3.endswith("foo.txt")

        fd1.close()
        fd2.close()
        fd3.close()


try:
    file_type = file
except NameError:
    import io
    file_type = io.TextIOWrapper  # type: ignore


class UniqueLineageNameTest(test_util.TempDirTestCase):
    """Tests for certbot.util.unique_lineage_name."""

    def _call(self, filename, mode=0o777):
        from certbot.util import unique_lineage_name
        return unique_lineage_name(self.tempdir, filename, mode)

    def test_basic(self):
        f, path = self._call("wow")
        assert isinstance(f, file_type)
        assert os.path.join(self.tempdir, "wow.conf") == path
        f.close()

    def test_multiple(self):
        items = []
        for _ in range(10):
            items.append(self._call("wow"))
        f, name = items[-1]
        assert isinstance(f, file_type)
        assert isinstance(name, str)
        assert "wow-0009.conf" in name
        for f, _ in items:
            f.close()

    def test_failure(self):
        with mock.patch("certbot.compat.filesystem.open", side_effect=OSError(errno.EIO)):
            with pytest.raises(OSError):
                self._call("wow")


class SafelyRemoveTest(test_util.TempDirTestCase):
    """Tests for certbot.util.safely_remove."""

    def setUp(self):
        super().setUp()

        self.path = os.path.join(self.tempdir, "foo")

    def _call(self):
        from certbot.util import safely_remove
        return safely_remove(self.path)

    def test_exists(self):
        with open(self.path, "w"):
            pass  # just create the file
        self._call()
        assert not os.path.exists(self.path)

    def test_missing(self):
        self._call()
        # no error, yay!
        assert not os.path.exists(self.path)

    def test_other_error_passthrough(self):
        with mock.patch("certbot.util.os.remove") as mock_remove:
            mock_remove.side_effect = OSError
            with pytest.raises(OSError):
                self._call()


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
            assert self._call(addr), "%s failed." % addr

    def test_invalid_emails(self):
        addrs = [
            "certbot@certbot..org",
            ".tbd.ade@gmail.com",
            "~/abc_def.jdk@hotmail.museum",
        ]
        for addr in addrs:
            assert not self._call(addr), "%s failed." % addr


class AddDeprecatedArgumentTest(unittest.TestCase):
    """Test add_deprecated_argument."""
    def setUp(self):
        self.parser = argparse.ArgumentParser()

    def _call(self, argument_name, nargs):
        from certbot.util import add_deprecated_argument
        add_deprecated_argument(self.parser.add_argument, argument_name, nargs)

    def test_warning_no_arg(self):
        self._call("--old-option", 0)
        with mock.patch("certbot.util.logger.warning") as mock_warn:
            self.parser.parse_args(["--old-option"])
        assert mock_warn.call_count == 1
        assert "is deprecated" in mock_warn.call_args[0][0]
        assert "--old-option" in mock_warn.call_args[0][1]

    def test_warning_with_arg(self):
        self._call("--old-option", 1)
        with mock.patch("certbot.util.logger.warning") as mock_warn:
            self.parser.parse_args(["--old-option", "42"])
        assert mock_warn.call_count == 1
        assert "is deprecated" in mock_warn.call_args[0][0]
        assert "--old-option" in mock_warn.call_args[0][1]

    def test_help(self):
        self._call("--old-option", 2)
        stdout = io.StringIO()
        with mock.patch("sys.stdout", new=stdout):
            try:
                self.parser.parse_args(["-h"])
            except SystemExit:
                pass
        assert "--old-option" not in stdout.getvalue()

    def test_set_constant(self):
        """Test when ACTION_TYPES_THAT_DONT_NEED_A_VALUE is a set.

        This variable is a set in configargparse versions < 0.12.0.

        """
        self._test_constant_common(set)

    def test_tuple_constant(self):
        """Test when ACTION_TYPES_THAT_DONT_NEED_A_VALUE is a tuple.

        This variable is a tuple in configargparse versions >= 0.12.0.

        """
        self._test_constant_common(tuple)

    def _test_constant_common(self, typ):
        with mock.patch("certbot.util.configargparse") as mock_configargparse:
            mock_configargparse.ACTION_TYPES_THAT_DONT_NEED_A_VALUE = typ()
            self._call("--old-option", 1)
            self._call("--old-option2", 2)
        assert len(mock_configargparse.ACTION_TYPES_THAT_DONT_NEED_A_VALUE) == 1


class EnforceLeValidity(unittest.TestCase):
    """Test enforce_le_validity."""
    def _call(self, domain):
        from certbot.util import enforce_le_validity
        return enforce_le_validity(domain)

    def test_sanity(self):
        with pytest.raises(errors.ConfigurationError):
            self._call(u"..")

    def test_invalid_chars(self):
        with pytest.raises(errors.ConfigurationError):
            self._call(u"hello_world.example.com")

    def test_leading_hyphen(self):
        with pytest.raises(errors.ConfigurationError):
            self._call(u"-a.example.com")

    def test_trailing_hyphen(self):
        with pytest.raises(errors.ConfigurationError):
            self._call(u"a-.example.com")

    def test_one_label(self):
        with pytest.raises(errors.ConfigurationError):
            self._call(u"com")

    def test_valid_domain(self):
        assert self._call(u"example.com") == u"example.com"

    def test_input_with_scheme(self):
        with pytest.raises(errors.ConfigurationError):
            self._call(u"http://example.com")
        with pytest.raises(errors.ConfigurationError):
            self._call(u"https://example.com")

    def test_valid_input_with_scheme_name(self):
        assert self._call(u"http.example.com") == u"http.example.com"


class EnforceDomainSanityTest(unittest.TestCase):
    """Test enforce_domain_sanity."""

    def _call(self, domain):
        from certbot.util import enforce_domain_sanity
        return enforce_domain_sanity(domain)

    def test_nonascii_str(self):
        with pytest.raises(errors.ConfigurationError):
            self._call(u"eichh\u00f6rnchen.example.com".encode("utf-8"))

    def test_nonascii_unicode(self):
        with pytest.raises(errors.ConfigurationError):
            self._call(u"eichh\u00f6rnchen.example.com")

    def test_too_long(self):
        long_domain = u"a"*256
        with pytest.raises(errors.ConfigurationError):
            self._call(long_domain)

    def test_not_too_long(self):
        not_too_long_domain = u"{0}.{1}.{2}.{3}".format("a"*63, "b"*63, "c"*63, "d"*63)
        self._call(not_too_long_domain)

    def test_empty_label(self):
        empty_label_domain = u"fizz..example.com"
        with pytest.raises(errors.ConfigurationError):
            self._call(empty_label_domain)

    def test_empty_trailing_label(self):
        empty_trailing_label_domain = u"example.com.."
        with pytest.raises(errors.ConfigurationError):
            self._call(empty_trailing_label_domain)

    def test_long_label_1(self):
        long_label_domain = u"a"*64
        with pytest.raises(errors.ConfigurationError):
            self._call(long_label_domain)

    def test_long_label_2(self):
        long_label_domain = u"{0}.{1}.com".format(u"a"*64, u"b"*63)
        with pytest.raises(errors.ConfigurationError):
            self._call(long_label_domain)

    def test_not_long_label(self):
        not_too_long_label_domain = u"{0}.{1}.com".format(u"a"*63, u"b"*63)
        self._call(not_too_long_label_domain)

    def test_empty_domain(self):
        empty_domain = u""
        with pytest.raises(errors.ConfigurationError):
            self._call(empty_domain)

    def test_punycode_ok(self):
        # Punycode is now legal, so no longer an error; instead check
        # that it's _not_ an error (at the initial sanity check stage)
        self._call('this.is.xn--ls8h.tld')


class IsWildcardDomainTest(unittest.TestCase):
    """Tests for is_wildcard_domain."""

    def setUp(self):
        self.wildcard = u"*.example.org"
        self.no_wildcard = u"example.org"

    def _call(self, domain):
        from certbot.util import is_wildcard_domain
        return is_wildcard_domain(domain)

    def test_no_wildcard(self):
        assert not self._call(self.no_wildcard)
        assert not self._call(self.no_wildcard.encode())

    def test_wildcard(self):
        assert self._call(self.wildcard)
        assert self._call(self.wildcard.encode())


class OsInfoTest(unittest.TestCase):
    """Test OS / distribution detection"""

    @mock.patch("certbot.util.distro")
    @unittest.skipUnless(sys.platform.startswith("linux"), "requires Linux")
    def test_systemd_os_release_like(self, m_distro):
        import certbot.util as cbutil
        m_distro.like.return_value = "first debian third"
        id_likes = cbutil.get_systemd_os_like()
        assert len(id_likes) == 3
        assert "debian" in id_likes

    @mock.patch("certbot.util.distro")
    @unittest.skipUnless(sys.platform.startswith("linux"), "requires Linux")
    def test_get_os_info_ua(self, m_distro):
        import certbot.util as cbutil
        with mock.patch('platform.system_alias',
                        return_value=('linux', '42', '42')):
            m_distro.version.return_value = "1.0"
            # empty value on first call for fallback to "get_python_os_info" in get_os_info_ua
            m_distro.name.side_effect = ["", "something", "something"]
            assert cbutil.get_os_info_ua() == \
                            " ".join(cbutil.get_python_os_info(pretty=True))

        m_distro.name.side_effect = ["whatever"]
        assert cbutil.get_os_info_ua() == "whatever"

    @mock.patch("certbot.util.distro")
    @unittest.skipUnless(sys.platform.startswith("linux"), "requires Linux")
    def test_get_os_info(self, m_distro):
        import certbot.util as cbutil
        with mock.patch("platform.system") as mock_platform:
            m_distro.id.return_value = "name"
            m_distro.version.return_value = "version"
            mock_platform.return_value = "linux"
            assert cbutil.get_os_info() == ("name", "version")

            m_distro.id.return_value = "something"
            m_distro.version.return_value = "else"
            assert cbutil.get_os_info() == ("something", "else")

    def test_non_systemd_os_info(self):
        import certbot.util as cbutil
        with mock.patch('certbot.util._USE_DISTRO', False):
            with mock.patch('platform.system_alias',
                            return_value=('NonSystemD', '42', '42')):
                assert cbutil.get_python_os_info()[0] == 'nonsystemd'

            with mock.patch('platform.system_alias',
                            return_value=('darwin', '', '')):
                with mock.patch("subprocess.run") as run_mock:
                    run_mock().stdout = '42.42.42'
                    assert cbutil.get_python_os_info()[0] == 'darwin'
                    assert cbutil.get_python_os_info()[1] == '42.42.42'

            with mock.patch('platform.system_alias',
                            return_value=('freebsd', '9.3-RC3-p1', '')):
                assert cbutil.get_python_os_info() == ("freebsd", "9")

            with mock.patch('platform.system_alias',
                            return_value=('windows', '', '')):
                with mock.patch('platform.win32_ver',
                                return_value=('4242', '95', '2', '')):
                    assert cbutil.get_python_os_info() == \
                                    ("windows", "95")

    @mock.patch("certbot.util.distro")
    @unittest.skipUnless(sys.platform.startswith("linux"), "requires Linux")
    def test_python_os_info_notfound(self, m_distro):
        import certbot.util as cbutil
        m_distro.id.return_value = ""
        m_distro.version.return_value = ""
        assert cbutil.get_python_os_info()[0] == "linux"

    @mock.patch("certbot.util.distro")
    @unittest.skipUnless(sys.platform.startswith("linux"), "requires Linux")
    def test_python_os_info_custom(self, m_distro):
        import certbot.util as cbutil
        m_distro.id.return_value = "testdist"
        m_distro.version.return_value = "42"
        assert cbutil.get_python_os_info() == ("testdist", "42")


class AtexitRegisterTest(unittest.TestCase):
    """Tests for certbot.util.atexit_register."""
    def setUp(self):
        self.func = mock.MagicMock()
        self.args = ('hi',)
        self.kwargs = {'answer': 42}

    @classmethod
    def _call(cls, *args, **kwargs):
        from certbot.util import atexit_register
        return atexit_register(*args, **kwargs)

    def test_called(self):
        self._test_common(os.getpid())
        self.func.assert_called_with(*self.args, **self.kwargs)

    def test_not_called(self):
        self._test_common(initial_pid=-1)
        assert self.func.called is False

    def _test_common(self, initial_pid):
        with mock.patch('certbot.util._INITIAL_PID', initial_pid):
            with mock.patch('certbot.util.atexit') as mock_atexit:
                self._call(self.func, *self.args, **self.kwargs)

            # _INITIAL_PID must be mocked when calling atexit_func
            assert mock_atexit.register.called
            args, kwargs = mock_atexit.register.call_args
            atexit_func = args[0]
            atexit_func(*args[1:], **kwargs)


class LooseVersionTest(unittest.TestCase):
    """Test for certbot.util.LooseVersion.

    These tests are based on the original tests for
    distutils.version.LooseVersion at
    https://github.com/python/cpython/blob/v3.10.0/Lib/distutils/tests/test_version.py#L58-L81.

    """

    @classmethod
    def _call(cls, *args, **kwargs):
        from certbot.util import LooseVersion
        return LooseVersion(*args, **kwargs)

    def test_less_than(self):
        comparisons = (('1.5.1', '1.5.2b2'),
            ('3.4j', '1996.07.12'),
            ('2g6', '11g'),
            ('0.960923', '2.2beta29'),
            ('1.13++', '5.5.kw'),
            ('2.0', '2.0.1'),
            ('a', 'b'))
        for v1, v2 in comparisons:
            assert self._call(v1) < self._call(v2)

    def test_equal(self):
        comparisons = (('8.02', '8.02'),
            ('1a', '1a'),
            ('2.0', '2.0.0'))
        for v1, v2 in comparisons:
            assert self._call(v1) == self._call(v2)

    def test_greater_than(self):
        comparisons = (('161', '3.10a'),
            ('3.2.pl0', '3.1.1.6'))
        for v1, v2 in comparisons:
            assert self._call(v1) > self._call(v2)

    def test_incomparible(self):
        comparisons = (('bookworm/sid', '9'),
            ('1a', '1.0'))
        for v1, v2 in comparisons:
            assert not self._call(v1) < self._call(v2)
            assert not self._call(v1) > self._call(v2)
            assert not self._call(v1) == self._call(v2)
            assert self._call(v1) != self._call(v2)


class ParseLooseVersionTest(unittest.TestCase):
    """Test for certbot.util.parse_loose_version.

    These tests are based on the original tests for
    distutils.version.LooseVersion at
    https://github.com/python/cpython/blob/v3.10.0/Lib/distutils/tests/test_version.py#L58-L81.

    """

    @classmethod
    def _call(cls, *args, **kwargs):
        from certbot.util import parse_loose_version
        return parse_loose_version(*args, **kwargs)

    def test_less_than(self):
        comparisons = (('1.5.1', '1.5.2b2'),
            ('3.4j', '1996.07.12'),
            ('2g6', '11g'),
            ('0.960923', '2.2beta29'),
            ('1.13++', '5.5.kw'))
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            for v1, v2 in comparisons:
                assert self._call(v1) < self._call(v2)

    def test_equal(self):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            assert self._call('8.02') == self._call('8.02')

    def test_greater_than(self):
        comparisons = (('161', '3.10a'),
            ('3.2.pl0', '3.1.1.6'))
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            for v1, v2 in comparisons:
                assert self._call(v1) > self._call(v2)


if __name__ == "__main__":
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover
