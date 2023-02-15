"""Tests for certbot.compat.filesystem"""
import contextlib
import errno
import sys
import unittest
from unittest import mock

import pytest

from certbot import util
from certbot._internal import lock
from certbot.compat import filesystem
from certbot.compat import os
import certbot.tests.util as test_util
from certbot.tests.util import TempDirTestCase

try:
    import ntsecuritycon
    import win32api
    import win32security
    POSIX_MODE = False
except ImportError:
    POSIX_MODE = True



EVERYBODY_SID = 'S-1-1-0'
SYSTEM_SID = 'S-1-5-18'
ADMINS_SID = 'S-1-5-32-544'


@unittest.skipIf(POSIX_MODE, reason='Tests specific to Windows security')
class WindowsChmodTests(TempDirTestCase):
    """Unit tests for Windows chmod function in filesystem module"""
    def setUp(self):
        super().setUp()
        self.probe_path = _create_probe(self.tempdir)

    def test_symlink_resolution(self):
        link_path = os.path.join(self.tempdir, 'link')
        os.symlink(self.probe_path, link_path)

        ref_dacl_probe = _get_security_dacl(self.probe_path).GetSecurityDescriptorDacl()
        ref_dacl_link = _get_security_dacl(link_path).GetSecurityDescriptorDacl()

        filesystem.chmod(link_path, 0o700)

        # Assert the real file is impacted, not the link.
        cur_dacl_probe = _get_security_dacl(self.probe_path).GetSecurityDescriptorDacl()
        cur_dacl_link = _get_security_dacl(link_path).GetSecurityDescriptorDacl()
        assert not filesystem._compare_dacls(ref_dacl_probe, cur_dacl_probe)  # pylint: disable=protected-access
        assert filesystem._compare_dacls(ref_dacl_link, cur_dacl_link)  # pylint: disable=protected-access

    def test_world_permission(self):
        everybody = win32security.ConvertStringSidToSid(EVERYBODY_SID)

        filesystem.chmod(self.probe_path, 0o700)
        dacl = _get_security_dacl(self.probe_path).GetSecurityDescriptorDacl()

        assert not [dacl.GetAce(index) for index in range(0, dacl.GetAceCount())
                          if dacl.GetAce(index)[2] == everybody]

        filesystem.chmod(self.probe_path, 0o704)
        dacl = _get_security_dacl(self.probe_path).GetSecurityDescriptorDacl()

        assert [dacl.GetAce(index) for index in range(0, dacl.GetAceCount())
                         if dacl.GetAce(index)[2] == everybody]

    def test_group_permissions_noop(self):
        filesystem.chmod(self.probe_path, 0o700)
        ref_dacl_probe = _get_security_dacl(self.probe_path).GetSecurityDescriptorDacl()

        filesystem.chmod(self.probe_path, 0o740)
        cur_dacl_probe = _get_security_dacl(self.probe_path).GetSecurityDescriptorDacl()

        assert filesystem._compare_dacls(ref_dacl_probe, cur_dacl_probe)  # pylint: disable=protected-access

    def test_admin_permissions(self):
        system = win32security.ConvertStringSidToSid(SYSTEM_SID)
        admins = win32security.ConvertStringSidToSid(ADMINS_SID)

        filesystem.chmod(self.probe_path, 0o400)
        dacl = _get_security_dacl(self.probe_path).GetSecurityDescriptorDacl()

        system_aces = [dacl.GetAce(index) for index in range(0, dacl.GetAceCount())
                       if dacl.GetAce(index)[2] == system]
        admin_aces = [dacl.GetAce(index) for index in range(0, dacl.GetAceCount())
                      if dacl.GetAce(index)[2] == admins]

        assert len(system_aces) == 1
        assert len(admin_aces) == 1

        assert system_aces[0][1] == ntsecuritycon.FILE_ALL_ACCESS
        assert admin_aces[0][1] == ntsecuritycon.FILE_ALL_ACCESS

    def test_read_flag(self):
        self._test_flag(4, ntsecuritycon.FILE_GENERIC_READ)

    def test_execute_flag(self):
        self._test_flag(1, ntsecuritycon.FILE_GENERIC_EXECUTE)

    def test_write_flag(self):
        self._test_flag(2, (ntsecuritycon.FILE_ALL_ACCESS
                            ^ ntsecuritycon.FILE_GENERIC_READ
                            ^ ntsecuritycon.FILE_GENERIC_EXECUTE))

    def test_full_flag(self):
        self._test_flag(7, ntsecuritycon.FILE_ALL_ACCESS)

    def _test_flag(self, everyone_mode, windows_flag):
        # Note that flag is tested against `everyone`, not `user`, because practically these unit
        # tests are executed with admin privilege, so current user is effectively the admins group,
        # and so will always have all rights.
        filesystem.chmod(self.probe_path, 0o700 | everyone_mode)
        dacl = _get_security_dacl(self.probe_path).GetSecurityDescriptorDacl()
        everybody = win32security.ConvertStringSidToSid(EVERYBODY_SID)

        acls_everybody = [dacl.GetAce(index) for index in range(0, dacl.GetAceCount())
                          if dacl.GetAce(index)[2] == everybody]

        assert len(acls_everybody) == 1

        acls_everybody = acls_everybody[0]

        assert acls_everybody[1] == windows_flag

    def test_user_admin_dacl_consistency(self):
        # Set ownership of target to authenticated user
        authenticated_user, _, _ = win32security.LookupAccountName("", win32api.GetUserName())
        security_owner = _get_security_owner(self.probe_path)
        _set_owner(self.probe_path, security_owner, authenticated_user)

        filesystem.chmod(self.probe_path, 0o700)

        security_dacl = _get_security_dacl(self.probe_path)
        # We expect three ACE: one for admins, one for system, and one for the user
        assert security_dacl.GetSecurityDescriptorDacl().GetAceCount() == 3

        # Set ownership of target to Administrators user group
        admin_user = win32security.ConvertStringSidToSid(ADMINS_SID)
        security_owner = _get_security_owner(self.probe_path)
        _set_owner(self.probe_path, security_owner, admin_user)

        filesystem.chmod(self.probe_path, 0o700)

        security_dacl = _get_security_dacl(self.probe_path)
        # We expect only two ACE: one for admins, one for system,
        # since the user is also the admins group
        assert security_dacl.GetSecurityDescriptorDacl().GetAceCount() == 2


class UmaskTest(TempDirTestCase):
    def test_umask_on_dir(self):
        previous_umask = filesystem.umask(0o022)

        try:
            dir1 = os.path.join(self.tempdir, 'probe1')
            filesystem.mkdir(dir1)
            assert filesystem.check_mode(dir1, 0o755) is True

            filesystem.umask(0o077)

            dir2 = os.path.join(self.tempdir, 'dir2')
            filesystem.mkdir(dir2)
            assert filesystem.check_mode(dir2, 0o700) is True

            dir3 = os.path.join(self.tempdir, 'dir3')
            filesystem.mkdir(dir3, mode=0o777)
            assert filesystem.check_mode(dir3, 0o700) is True
        finally:
            filesystem.umask(previous_umask)

    def test_umask_on_file(self):
        previous_umask = filesystem.umask(0o022)

        try:
            file1 = os.path.join(self.tempdir, 'probe1')
            UmaskTest._create_file(file1)
            assert filesystem.check_mode(file1, 0o755) is True

            filesystem.umask(0o077)

            file2 = os.path.join(self.tempdir, 'probe2')
            UmaskTest._create_file(file2)
            assert filesystem.check_mode(file2, 0o700) is True

            file3 = os.path.join(self.tempdir, 'probe3')
            UmaskTest._create_file(file3)
            assert filesystem.check_mode(file3, 0o700) is True
        finally:
            filesystem.umask(previous_umask)

    @staticmethod
    def _create_file(path, mode=0o777):
        file_desc = None
        try:
            file_desc = filesystem.open(path, flags=os.O_CREAT, mode=mode)
        finally:
            if file_desc:
                os.close(file_desc)


class ComputePrivateKeyModeTest(TempDirTestCase):
    def setUp(self):
        super().setUp()
        self.probe_path = _create_probe(self.tempdir)

    def test_compute_private_key_mode(self):
        filesystem.chmod(self.probe_path, 0o777)
        new_mode = filesystem.compute_private_key_mode(self.probe_path, 0o600)

        if POSIX_MODE:
            # On Linux RWX permissions for group and R permission for world
            # are persisted from the existing moe
            assert new_mode == 0o674
        else:
            # On Windows no permission is persisted
            assert new_mode == 0o600


@unittest.skipIf(POSIX_MODE, reason='Tests specific to Windows security')
class WindowsOpenTest(TempDirTestCase):
    def test_new_file_correct_permissions(self):
        path = os.path.join(self.tempdir, 'file')

        desc = filesystem.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o700)
        os.close(desc)

        dacl = _get_security_dacl(path).GetSecurityDescriptorDacl()
        everybody = win32security.ConvertStringSidToSid(EVERYBODY_SID)

        assert not [dacl.GetAce(index) for index in range(0, dacl.GetAceCount())
                          if dacl.GetAce(index)[2] == everybody]

    def test_existing_file_correct_permissions(self):
        path = os.path.join(self.tempdir, 'file')
        open(path, 'w').close()

        desc = filesystem.open(path, os.O_EXCL | os.O_RDWR, 0o700)
        os.close(desc)

        dacl = _get_security_dacl(path).GetSecurityDescriptorDacl()
        everybody = win32security.ConvertStringSidToSid(EVERYBODY_SID)

        assert not [dacl.GetAce(index) for index in range(0, dacl.GetAceCount())
                          if dacl.GetAce(index)[2] == everybody]

    def test_create_file_on_open(self):
        # os.O_CREAT | os.O_EXCL + file not exists = OK
        self._test_one_creation(1, file_exist=False, flags=(os.O_CREAT | os.O_EXCL))

        # os.O_CREAT | os.O_EXCL + file exists = EEXIST OS exception
        with pytest.raises(OSError) as exc_info:
            self._test_one_creation(2, file_exist=True, flags=(os.O_CREAT | os.O_EXCL))
        assert exc_info.value.errno == errno.EEXIST

        # os.O_CREAT + file not exists = OK
        self._test_one_creation(3, file_exist=False, flags=os.O_CREAT)

        # os.O_CREAT + file exists = OK
        self._test_one_creation(4, file_exist=True, flags=os.O_CREAT)

        # os.O_CREAT + file exists (locked) = EACCES OS exception
        path = os.path.join(self.tempdir, '5')
        open(path, 'w').close()
        filelock = lock.LockFile(path)
        try:
            with pytest.raises(OSError) as exc_info:
                self._test_one_creation(5, file_exist=True, flags=os.O_CREAT)
            assert exc_info.value.errno == errno.EACCES
        finally:
            filelock.release()

        # os.O_CREAT not set + file not exists = OS exception
        with pytest.raises(OSError):
            self._test_one_creation(6, file_exist=False, flags=os.O_RDONLY)

    def _test_one_creation(self, num, file_exist, flags):
        one_file = os.path.join(self.tempdir, str(num))
        if file_exist and not os.path.exists(one_file):
            with open(one_file, 'w'):
                pass

        handler = None
        try:
            handler = filesystem.open(one_file, flags)
        finally:
            if handler:
                os.close(handler)


class TempUmaskTests(test_util.TempDirTestCase):
    """Tests for using the TempUmask class in `with` statements"""
    def _check_umask(self):
        old_umask = filesystem.umask(0)
        filesystem.umask(old_umask)
        return old_umask

    def test_works_normally(self):
        filesystem.umask(0o0022)
        assert self._check_umask() == 0o0022
        with filesystem.temp_umask(0o0077):
            assert self._check_umask() == 0o0077
        assert self._check_umask() == 0o0022

    def test_resets_umask_after_exception(self):
        filesystem.umask(0o0022)
        assert self._check_umask() == 0o0022
        try:
            with filesystem.temp_umask(0o0077):
                assert self._check_umask() == 0o0077
                raise Exception()
        except:
            assert self._check_umask() == 0o0022


@unittest.skipIf(POSIX_MODE, reason='Test specific to Windows security')
class WindowsMkdirTests(test_util.TempDirTestCase):
    """Unit tests for Windows mkdir + makedirs functions in filesystem module"""
    def test_mkdir_correct_permissions(self):
        path = os.path.join(self.tempdir, 'dir')

        filesystem.mkdir(path, 0o700)

        everybody = win32security.ConvertStringSidToSid(EVERYBODY_SID)

        dacl = _get_security_dacl(path).GetSecurityDescriptorDacl()
        assert not [dacl.GetAce(index) for index in range(0, dacl.GetAceCount())
                          if dacl.GetAce(index)[2] == everybody]

    def test_makedirs_correct_permissions(self):
        path = os.path.join(self.tempdir, 'dir')
        subpath = os.path.join(path, 'subpath')

        filesystem.makedirs(subpath, 0o700)

        everybody = win32security.ConvertStringSidToSid(EVERYBODY_SID)

        dacl = _get_security_dacl(subpath).GetSecurityDescriptorDacl()
        assert not [dacl.GetAce(index) for index in range(0, dacl.GetAceCount())
                          if dacl.GetAce(index)[2] == everybody]

    def test_makedirs_switch_os_mkdir(self):
        path = os.path.join(self.tempdir, 'dir')
        import os as std_os  # pylint: disable=os-module-forbidden
        original_mkdir = std_os.mkdir

        filesystem.makedirs(path)
        assert original_mkdir == std_os.mkdir

        try:
            filesystem.makedirs(path)  # Will fail because path already exists
        except OSError:
            pass
        assert original_mkdir == std_os.mkdir


class MakedirsTests(test_util.TempDirTestCase):
    """Unit tests for makedirs function in filesystem module"""
    def test_makedirs_correct_permissions(self):
        path = os.path.join(self.tempdir, 'dir')
        subpath = os.path.join(path, 'subpath')

        previous_umask = filesystem.umask(0o022)

        try:
            filesystem.makedirs(subpath, 0o700)

            assert filesystem.check_mode(path, 0o700)
            assert filesystem.check_mode(subpath, 0o700)
        finally:
            filesystem.umask(previous_umask)


class CopyOwnershipAndModeTest(test_util.TempDirTestCase):
    """Tests about copy_ownership_and_apply_mode, copy_ownership_and_mode and has_same_ownership"""
    def setUp(self):
        super().setUp()
        self.probe_path = _create_probe(self.tempdir)

    @unittest.skipIf(POSIX_MODE, reason='Test specific to Windows security')
    def test_copy_ownership_and_apply_mode_windows(self):
        system = win32security.ConvertStringSidToSid(SYSTEM_SID)
        security = win32security.SECURITY_ATTRIBUTES().SECURITY_DESCRIPTOR
        security.SetSecurityDescriptorOwner(system, False)

        with mock.patch('win32security.GetFileSecurity') as mock_get:
            with mock.patch('win32security.SetFileSecurity') as mock_set:
                mock_get.return_value = security
                filesystem.copy_ownership_and_apply_mode(
                    'dummy', self.probe_path, 0o700, copy_user=True, copy_group=False)

        assert mock_set.call_count == 2

        first_call = mock_set.call_args_list[0]
        security = first_call[0][2]
        assert system == security.GetSecurityDescriptorOwner()

        second_call = mock_set.call_args_list[1]
        security = second_call[0][2]
        dacl = security.GetSecurityDescriptorDacl()
        everybody = win32security.ConvertStringSidToSid(EVERYBODY_SID)
        assert dacl.GetAceCount()
        assert not [dacl.GetAce(index) for index in range(0, dacl.GetAceCount())
                          if dacl.GetAce(index)[2] == everybody]

    @unittest.skipUnless(POSIX_MODE, reason='Test specific to Linux security')
    def test_copy_ownership_and_apply_mode_linux(self):
        with mock.patch('os.chown') as mock_chown:
            with mock.patch('os.chmod') as mock_chmod:
                with mock.patch('os.stat') as mock_stat:
                    mock_stat.return_value.st_uid = 50
                    mock_stat.return_value.st_gid = 51
                    filesystem.copy_ownership_and_apply_mode(
                        'dummy', self.probe_path, 0o700, copy_user=True, copy_group=True)

        mock_chown.assert_called_once_with(self.probe_path, 50, 51)
        mock_chmod.assert_called_once_with(self.probe_path, 0o700)

    def test_has_same_ownership(self):
        path1 = os.path.join(self.tempdir, 'test1')
        path2 = os.path.join(self.tempdir, 'test2')

        util.safe_open(path1, 'w').close()
        util.safe_open(path2, 'w').close()

        assert filesystem.has_same_ownership(path1, path2) is True

    @unittest.skipIf(POSIX_MODE, reason='Test specific to Windows security')
    def test_copy_ownership_and_mode_windows(self):
        src = self.probe_path
        dst = _create_probe(self.tempdir, name='dst')

        filesystem.chmod(src, 0o700)
        assert filesystem.check_mode(src, 0o700) is True
        assert filesystem.check_mode(dst, 0o744) is True

        # Checking an actual change of owner is tricky during a unit test, since we do not know
        # if any user exists beside the current one. So we mock _copy_win_ownership. It's behavior
        # have been checked theoretically with test_copy_ownership_and_apply_mode_windows.
        with mock.patch('certbot.compat.filesystem._copy_win_ownership') as mock_copy_owner:
            filesystem.copy_ownership_and_mode(src, dst)

        mock_copy_owner.assert_called_once_with(src, dst)
        assert filesystem.check_mode(dst, 0o700) is True


class CheckPermissionsTest(test_util.TempDirTestCase):
    """Tests relative to functions that check modes."""
    def setUp(self):
        super().setUp()
        self.probe_path = _create_probe(self.tempdir)

    def test_check_mode(self):
        assert filesystem.check_mode(self.probe_path, 0o744) is True

        filesystem.chmod(self.probe_path, 0o700)
        assert not filesystem.check_mode(self.probe_path, 0o744)

    @unittest.skipIf(POSIX_MODE, reason='Test specific to Windows security')
    def test_check_owner_windows(self):
        assert filesystem.check_owner(self.probe_path) is True

        system = win32security.ConvertStringSidToSid(SYSTEM_SID)
        security = win32security.SECURITY_ATTRIBUTES().SECURITY_DESCRIPTOR
        security.SetSecurityDescriptorOwner(system, False)

        with mock.patch('win32security.GetFileSecurity') as mock_get:
            mock_get.return_value = security
            assert not filesystem.check_owner(self.probe_path)

    @unittest.skipUnless(POSIX_MODE, reason='Test specific to Linux security')
    def test_check_owner_linux(self):
        assert filesystem.check_owner(self.probe_path) is True

        import os as std_os  # pylint: disable=os-module-forbidden

        # See related inline comment in certbot.compat.filesystem.check_owner method
        # that explains why MyPy/PyLint check disable is needed here.
        uid = std_os.getuid()

        with mock.patch('os.getuid') as mock_uid:
            mock_uid.return_value = uid + 1
            assert not filesystem.check_owner(self.probe_path)

    def test_check_permissions(self):
        assert filesystem.check_permissions(self.probe_path, 0o744) is True

        with mock.patch('certbot.compat.filesystem.check_mode') as mock_mode:
            mock_mode.return_value = False
            assert not filesystem.check_permissions(self.probe_path, 0o744)

        with mock.patch('certbot.compat.filesystem.check_owner') as mock_owner:
            mock_owner.return_value = False
            assert not filesystem.check_permissions(self.probe_path, 0o744)

    def test_check_min_permissions(self):
        filesystem.chmod(self.probe_path, 0o744)
        assert filesystem.has_min_permissions(self.probe_path, 0o744) is True

        filesystem.chmod(self.probe_path, 0o700)
        assert not filesystem.has_min_permissions(self.probe_path, 0o744)

        filesystem.chmod(self.probe_path, 0o741)
        assert not filesystem.has_min_permissions(self.probe_path, 0o744)

    def test_is_world_reachable(self):
        filesystem.chmod(self.probe_path, 0o744)
        assert filesystem.has_world_permissions(self.probe_path) is True

        filesystem.chmod(self.probe_path, 0o700)
        assert not filesystem.has_world_permissions(self.probe_path)


class OsReplaceTest(test_util.TempDirTestCase):
    """Test to ensure consistent behavior of rename method"""
    def test_os_replace_to_existing_file(self):
        """Ensure that replace will effectively rename src into dst for all platforms."""
        src = os.path.join(self.tempdir, 'src')
        dst = os.path.join(self.tempdir, 'dst')
        open(src, 'w').close()
        open(dst, 'w').close()

        # On Windows, a direct call to os.rename would fail because dst already exists.
        filesystem.replace(src, dst)

        assert not os.path.exists(src)
        assert os.path.exists(dst) is True


class RealpathTest(test_util.TempDirTestCase):
    """Tests for realpath method"""
    def setUp(self):
        super().setUp()
        self.probe_path = _create_probe(self.tempdir)

    def test_symlink_resolution(self):
        # Remove any symlinks already in probe_path
        self.probe_path = filesystem.realpath(self.probe_path)
        # Absolute resolution
        link_path = os.path.join(self.tempdir, 'link_abs')
        os.symlink(self.probe_path, link_path)

        assert self.probe_path == filesystem.realpath(self.probe_path)
        assert self.probe_path == filesystem.realpath(link_path)

        # Relative resolution
        curdir = os.getcwd()
        link_path = os.path.join(self.tempdir, 'link_rel')
        probe_name = os.path.basename(self.probe_path)
        try:
            os.chdir(os.path.dirname(self.probe_path))
            os.symlink(probe_name, link_path)

            assert self.probe_path == filesystem.realpath(probe_name)
            assert self.probe_path == filesystem.realpath(link_path)
        finally:
            os.chdir(curdir)

    def test_symlink_loop_mitigation(self):
        link1_path = os.path.join(self.tempdir, 'link1')
        link2_path = os.path.join(self.tempdir, 'link2')
        link3_path = os.path.join(self.tempdir, 'link3')
        os.symlink(link1_path, link2_path)
        os.symlink(link2_path, link3_path)
        os.symlink(link3_path, link1_path)

        with pytest.raises(RuntimeError, match='link1 is a loop!') as error:
            filesystem.realpath(link1_path)


class IsExecutableTest(test_util.TempDirTestCase):
    """Tests for is_executable method"""
    def test_not_executable(self):
        file_path = os.path.join(self.tempdir, "foo")

        # On Windows a file created within Certbot will always have all permissions to the
        # Administrators group set. Since the unit tests are typically executed under elevated
        # privileges, it means that current user will always have effective execute rights on the
        # hook script, and so the test will fail. To prevent that and represent a file created
        # outside Certbot as typically a hook file is, we mock the _generate_dacl function in
        # certbot.compat.filesystem to give rights only to the current user. This implies removing
        # all ACEs except the first one from the DACL created by original _generate_dacl function.

        from certbot.compat.filesystem import _generate_dacl

        def _execute_mock(user_sid, mode, mask=None):
            dacl = _generate_dacl(user_sid, mode, mask)
            for _ in range(1, dacl.GetAceCount()):
                dacl.DeleteAce(1)  # DeleteAce dynamically updates the internal index mapping.
            return dacl

        # create a non-executable file
        with mock.patch("certbot.compat.filesystem._generate_dacl", side_effect=_execute_mock):
            os.close(filesystem.open(file_path, os.O_CREAT | os.O_WRONLY, 0o666))

        assert not filesystem.is_executable(file_path)

    @mock.patch("certbot.compat.filesystem.os.path.isfile")
    @mock.patch("certbot.compat.filesystem.os.access")
    def test_full_path(self, mock_access, mock_isfile):
        with _fix_windows_runtime():
            mock_access.return_value = True
            mock_isfile.return_value = True
            assert filesystem.is_executable("/path/to/exe") is True

    @mock.patch("certbot.compat.filesystem.os.path.isfile")
    @mock.patch("certbot.compat.filesystem.os.access")
    def test_rel_path(self, mock_access, mock_isfile):
        with _fix_windows_runtime():
            mock_access.return_value = True
            mock_isfile.return_value = True
            assert filesystem.is_executable("exe") is True

    @mock.patch("certbot.compat.filesystem.os.path.isfile")
    @mock.patch("certbot.compat.filesystem.os.access")
    def test_not_found(self, mock_access, mock_isfile):
        with _fix_windows_runtime():
            mock_access.return_value = True
            mock_isfile.return_value = False
            assert not filesystem.is_executable("exe")


class ReadlinkTest(unittest.TestCase):
    @unittest.skipUnless(POSIX_MODE, reason='Tests specific to Linux')
    @mock.patch("certbot.compat.filesystem.os.readlink")
    def test_path_posix(self, mock_readlink):
        mock_readlink.return_value = "/normal/path"
        assert filesystem.readlink("dummy") == "/normal/path"

    @unittest.skipIf(POSIX_MODE, reason='Tests specific to Windows')
    @mock.patch("certbot.compat.filesystem.os.readlink")
    def test_normal_path_windows(self, mock_readlink):
        # Python <3.8
        mock_readlink.return_value = "C:\\short\\path"
        assert filesystem.readlink("dummy") == "C:\\short\\path"

        # Python >=3.8 (os.readlink always returns the extended form)
        mock_readlink.return_value = "\\\\?\\C:\\short\\path"
        assert filesystem.readlink("dummy") == "C:\\short\\path"

    @unittest.skipIf(POSIX_MODE, reason='Tests specific to Windows')
    @mock.patch("certbot.compat.filesystem.os.readlink")
    def test_extended_path_windows(self, mock_readlink):
        # Following path is largely over the 260 characters permitted in the normal form.
        mock_readlink.return_value = "\\\\?\\C:\\long" + 1000 * "\\path"
        with pytest.raises(ValueError):
            filesystem.readlink("dummy")

@contextlib.contextmanager
def _fix_windows_runtime():
    if os.name != 'nt':
        yield
    else:
        with mock.patch('win32security.GetFileSecurity') as mock_get:
            dacl_mock = mock_get.return_value.GetSecurityDescriptorDacl
            mode_mock = dacl_mock.return_value.GetEffectiveRightsFromAcl
            mode_mock.return_value = ntsecuritycon.FILE_GENERIC_EXECUTE
            yield


def _get_security_dacl(target):
    return win32security.GetFileSecurity(target, win32security.DACL_SECURITY_INFORMATION)


def _get_security_owner(target):
    return win32security.GetFileSecurity(target, win32security.OWNER_SECURITY_INFORMATION)


def _set_owner(target, security_owner, user):
    security_owner.SetSecurityDescriptorOwner(user, False)
    win32security.SetFileSecurity(
        target, win32security.OWNER_SECURITY_INFORMATION, security_owner)


def _create_probe(tempdir, name='probe'):
    filesystem.chmod(tempdir, 0o744)
    probe_path = os.path.join(tempdir, name)
    util.safe_open(probe_path, 'w', chmod=0o744).close()
    return probe_path


if __name__ == "__main__":
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover
