"""Tests for certbot.compat.filesystem"""
import errno
import unittest

import mock

try:
    # pylint: disable=import-error
    import win32api
    import win32security
    import ntsecuritycon
    # pylint: enable=import-error
    POSIX_MODE = False
except ImportError:
    POSIX_MODE = True

import certbot.tests.util as test_util
from certbot import lock
from certbot.compat import os
from certbot.compat import filesystem
from certbot.tests.util import TempDirTestCase


EVERYBODY_SID = 'S-1-1-0'
SYSTEM_SID = 'S-1-5-18'
ADMINS_SID = 'S-1-5-32-544'


@unittest.skipIf(POSIX_MODE, reason='Tests specific to Windows security')
class WindowsChmodTests(TempDirTestCase):
    """Unit tests for Windows chmod function in filesystem module"""
    def setUp(self):
        super(WindowsChmodTests, self).setUp()
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
        self.assertFalse(filesystem._compare_dacls(ref_dacl_probe, cur_dacl_probe))  # pylint: disable=protected-access
        self.assertTrue(filesystem._compare_dacls(ref_dacl_link, cur_dacl_link))  # pylint: disable=protected-access

    def test_symlink_loop_mitigation(self):
        link1_path = os.path.join(self.tempdir, 'link1')
        link2_path = os.path.join(self.tempdir, 'link2')
        link3_path = os.path.join(self.tempdir, 'link3')
        os.symlink(link1_path, link2_path)
        os.symlink(link2_path, link3_path)
        os.symlink(link3_path, link1_path)

        with self.assertRaises(RuntimeError) as error:
            filesystem.chmod(link1_path, 0o755)
        self.assertTrue('link1 is a loop!' in str(error.exception))

    def test_world_permission(self):
        everybody = win32security.ConvertStringSidToSid(EVERYBODY_SID)

        filesystem.chmod(self.probe_path, 0o700)
        dacl = _get_security_dacl(self.probe_path).GetSecurityDescriptorDacl()

        self.assertFalse([dacl.GetAce(index) for index in range(0, dacl.GetAceCount())
                          if dacl.GetAce(index)[2] == everybody])

        filesystem.chmod(self.probe_path, 0o704)
        dacl = _get_security_dacl(self.probe_path).GetSecurityDescriptorDacl()

        self.assertTrue([dacl.GetAce(index) for index in range(0, dacl.GetAceCount())
                         if dacl.GetAce(index)[2] == everybody])

    def test_group_permissions_noop(self):
        filesystem.chmod(self.probe_path, 0o700)
        ref_dacl_probe = _get_security_dacl(self.probe_path).GetSecurityDescriptorDacl()

        filesystem.chmod(self.probe_path, 0o740)
        cur_dacl_probe = _get_security_dacl(self.probe_path).GetSecurityDescriptorDacl()

        self.assertTrue(filesystem._compare_dacls(ref_dacl_probe, cur_dacl_probe))  # pylint: disable=protected-access

    def test_admin_permissions(self):
        system = win32security.ConvertStringSidToSid(SYSTEM_SID)
        admins = win32security.ConvertStringSidToSid(ADMINS_SID)

        filesystem.chmod(self.probe_path, 0o400)
        dacl = _get_security_dacl(self.probe_path).GetSecurityDescriptorDacl()

        system_aces = [dacl.GetAce(index) for index in range(0, dacl.GetAceCount())
                       if dacl.GetAce(index)[2] == system]
        admin_aces = [dacl.GetAce(index) for index in range(0, dacl.GetAceCount())
                      if dacl.GetAce(index)[2] == admins]

        self.assertEqual(len(system_aces), 1)
        self.assertEqual(len(admin_aces), 1)

        self.assertEqual(system_aces[0][1], ntsecuritycon.FILE_ALL_ACCESS ^ 512)
        self.assertEqual(admin_aces[0][1], ntsecuritycon.FILE_ALL_ACCESS ^ 512)

    def test_read_flag(self):
        self._test_flag(4, ntsecuritycon.FILE_GENERIC_READ)

    def test_execute_flag(self):
        self._test_flag(1, ntsecuritycon.FILE_GENERIC_EXECUTE)

    def test_write_flag(self):
        self._test_flag(2, (ntsecuritycon.FILE_ALL_ACCESS
                            ^ ntsecuritycon.FILE_GENERIC_READ
                            ^ ntsecuritycon.FILE_GENERIC_EXECUTE
                            ^ 512))

    def test_full_flag(self):
        self._test_flag(7, (ntsecuritycon.FILE_ALL_ACCESS
                            ^ 512))

    def _test_flag(self, everyone_mode, windows_flag):
        # Note that flag is tested against `everyone`, not `user`, because practically these unit
        # tests are executed with admin privilege, so current user is effectively the admins group,
        # and so will always have all rights.
        filesystem.chmod(self.probe_path, 0o700 | everyone_mode)
        dacl = _get_security_dacl(self.probe_path).GetSecurityDescriptorDacl()
        everybody = win32security.ConvertStringSidToSid(EVERYBODY_SID)

        acls_everybody = [dacl.GetAce(index) for index in range(0, dacl.GetAceCount())
                          if dacl.GetAce(index)[2] == everybody]

        self.assertEqual(len(acls_everybody), 1)

        acls_everybody = acls_everybody[0]

        self.assertEqual(acls_everybody[1], windows_flag)

    def test_user_admin_dacl_consistency(self):
        # Set ownership of target to authenticated user
        authenticated_user, _, _ = win32security.LookupAccountName("", win32api.GetUserName())
        security_owner = _get_security_owner(self.probe_path)
        _set_owner(self.probe_path, security_owner, authenticated_user)

        filesystem.chmod(self.probe_path, 0o700)

        security_dacl = _get_security_dacl(self.probe_path)
        # We expect three ACE: one for admins, one for system, and one for the user
        self.assertEqual(security_dacl.GetSecurityDescriptorDacl().GetAceCount(), 3)

        # Set ownership of target to Administrators user group
        admin_user = win32security.ConvertStringSidToSid(ADMINS_SID)
        security_owner = _get_security_owner(self.probe_path)
        _set_owner(self.probe_path, security_owner, admin_user)

        filesystem.chmod(self.probe_path, 0o700)

        security_dacl = _get_security_dacl(self.probe_path)
        # We expect only two ACE: one for admins, one for system,
        # since the user is also the admins group
        self.assertEqual(security_dacl.GetSecurityDescriptorDacl().GetAceCount(), 2)


@unittest.skipIf(POSIX_MODE, reason='Tests specific to Windows security')
class WindowsOpenTest(TempDirTestCase):
    def test_new_file_correct_permissions(self):
        path = os.path.join(self.tempdir, 'file')

        desc = filesystem.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o700)
        os.close(desc)

        dacl = _get_security_dacl(path).GetSecurityDescriptorDacl()
        everybody = win32security.ConvertStringSidToSid(EVERYBODY_SID)

        self.assertFalse([dacl.GetAce(index) for index in range(0, dacl.GetAceCount())
                          if dacl.GetAce(index)[2] == everybody])

    def test_existing_file_correct_permissions(self):
        path = os.path.join(self.tempdir, 'file')
        open(path, 'w').close()

        desc = filesystem.open(path, os.O_EXCL | os.O_RDWR, 0o700)
        os.close(desc)

        dacl = _get_security_dacl(path).GetSecurityDescriptorDacl()
        everybody = win32security.ConvertStringSidToSid(EVERYBODY_SID)

        self.assertFalse([dacl.GetAce(index) for index in range(0, dacl.GetAceCount())
                          if dacl.GetAce(index)[2] == everybody])

    def test_create_file_on_open(self):
        # os.O_CREAT | os.O_EXCL + file not exists = OK
        self._test_one_creation(1, file_exist=False, flags=(os.O_CREAT | os.O_EXCL))

        # os.O_CREAT | os.O_EXCL + file exists = EEXIST OS exception
        with self.assertRaises(OSError) as raised:
            self._test_one_creation(2, file_exist=True, flags=(os.O_CREAT | os.O_EXCL))
        self.assertEqual(raised.exception.errno, errno.EEXIST)

        # os.O_CREAT + file not exists = OK
        self._test_one_creation(3, file_exist=False, flags=os.O_CREAT)

        # os.O_CREAT + file exists = OK
        self._test_one_creation(4, file_exist=True, flags=os.O_CREAT)

        # os.O_CREAT + file exists (locked) = EACCES OS exception
        path = os.path.join(self.tempdir, '5')
        open(path, 'w').close()
        filelock = lock.LockFile(path)
        try:
            with self.assertRaises(OSError) as raised:
                self._test_one_creation(5, file_exist=True, flags=os.O_CREAT)
            self.assertEqual(raised.exception.errno, errno.EACCES)
        finally:
            filelock.release()

        # os.O_CREAT not set + file not exists = OS exception
        with self.assertRaises(OSError):
            self._test_one_creation(6, file_exist=False, flags=os.O_RDONLY)

    def _test_one_creation(self, num, file_exist, flags):
        one_file = os.path.join(self.tempdir, str(num))
        if file_exist and not os.path.exists(one_file):
            open(one_file, 'w').close()

        handler = None
        try:
            handler = filesystem.open(one_file, flags)
        except BaseException as err:
            if handler:
                os.close(handler)
            raise err


@unittest.skipIf(POSIX_MODE, reason='Test specific to Windows security')
class WindowsMkdirTests(test_util.TempDirTestCase):
    """Unit tests for Windows mkdir + makedirs functions in filesystem module"""
    def test_mkdir_correct_permissions(self):
        path = os.path.join(self.tempdir, 'dir')

        filesystem.mkdir(path, 0o700)

        everybody = win32security.ConvertStringSidToSid(EVERYBODY_SID)

        dacl = _get_security_dacl(path).GetSecurityDescriptorDacl()
        self.assertFalse([dacl.GetAce(index) for index in range(0, dacl.GetAceCount())
                          if dacl.GetAce(index)[2] == everybody])

    def test_makedirs_correct_permissions(self):
        path = os.path.join(self.tempdir, 'dir')
        subpath = os.path.join(path, 'subpath')

        filesystem.makedirs(subpath, 0o700)

        everybody = win32security.ConvertStringSidToSid(EVERYBODY_SID)

        dacl = _get_security_dacl(subpath).GetSecurityDescriptorDacl()
        self.assertFalse([dacl.GetAce(index) for index in range(0, dacl.GetAceCount())
                          if dacl.GetAce(index)[2] == everybody])

    def test_makedirs_switch_os_mkdir(self):
        path = os.path.join(self.tempdir, 'dir')
        import os as std_os  # pylint: disable=os-module-forbidden
        original_mkdir = std_os.mkdir

        filesystem.makedirs(path)
        self.assertEqual(original_mkdir, std_os.mkdir)

        try:
            filesystem.makedirs(path)  # Will fail because path already exists
        except OSError:
            pass
        self.assertEqual(original_mkdir, std_os.mkdir)


class CopyOwnershipTest(test_util.TempDirTestCase):
    """Tests about replacement of chown: copy_ownership_and_apply_mode"""
    def setUp(self):
        super(CopyOwnershipTest, self).setUp()
        self.probe_path = _create_probe(self.tempdir)

    @unittest.skipIf(POSIX_MODE, reason='Test specific to Windows security')
    def test_windows(self):
        system = win32security.ConvertStringSidToSid(SYSTEM_SID)
        security = win32security.SECURITY_ATTRIBUTES().SECURITY_DESCRIPTOR
        security.SetSecurityDescriptorOwner(system, False)

        with mock.patch('win32security.GetFileSecurity') as mock_get:
            with mock.patch('win32security.SetFileSecurity') as mock_set:
                mock_get.return_value = security
                filesystem.copy_ownership_and_apply_mode(
                    'dummy', self.probe_path, 0o700, copy_user=True, copy_group=False)

        self.assertEqual(mock_set.call_count, 2)

        first_call = mock_set.call_args_list[0]
        security = first_call[0][2]
        self.assertEqual(system, security.GetSecurityDescriptorOwner())

        second_call = mock_set.call_args_list[1]
        security = second_call[0][2]
        dacl = security.GetSecurityDescriptorDacl()
        everybody = win32security.ConvertStringSidToSid(EVERYBODY_SID)
        self.assertTrue(dacl.GetAceCount())
        self.assertFalse([dacl.GetAce(index) for index in range(0, dacl.GetAceCount())
                          if dacl.GetAce(index)[2] == everybody])

    @unittest.skipUnless(POSIX_MODE, reason='Test specific to Linux security')
    def test_linux(self):
        with mock.patch('os.chown') as mock_chown:
            with mock.patch('os.chmod') as mock_chmod:
                with mock.patch('os.stat') as mock_stat:
                    mock_stat.return_value.st_uid = 50
                    mock_stat.return_value.st_gid = 51
                    filesystem.copy_ownership_and_apply_mode(
                        'dummy', self.probe_path, 0o700, copy_user=True, copy_group=True)

        mock_chown.assert_called_once_with(self.probe_path, 50, 51)
        mock_chmod.assert_called_once_with(self.probe_path, 0o700)


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

        self.assertFalse(os.path.exists(src))
        self.assertTrue(os.path.exists(dst))


def _get_security_dacl(target):
    return win32security.GetFileSecurity(target, win32security.DACL_SECURITY_INFORMATION)


def _get_security_owner(target):
    return win32security.GetFileSecurity(target, win32security.OWNER_SECURITY_INFORMATION)


def _set_owner(target, security_owner, user):
    security_owner.SetSecurityDescriptorOwner(user, False)
    win32security.SetFileSecurity(
        target, win32security.OWNER_SECURITY_INFORMATION, security_owner)


def _create_probe(tempdir):
    filesystem.chmod(tempdir, 0o744)
    probe_path = os.path.join(tempdir, 'probe')
    open(probe_path, 'w').close()
    return probe_path


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
