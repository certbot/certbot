"""Tests for certbot.compat.filesystem"""
import unittest

try:
    import win32api  # pylint: disable=import-error
    import win32security  # pylint: disable=import-error
    import ntsecuritycon  # pylint: disable=import-error
    POSIX_MODE = False
except ImportError:
    POSIX_MODE = True

import certbot.tests.util as test_util
from certbot.compat import os
from certbot.compat import filesystem
from certbot.tests.util import TempDirTestCase


EVERYBODY_SID = 'S-1-1-0'
SYSTEM_SID = 'S-1-5-18'
ADMINS_SID = 'S-1-5-32-544'


@unittest.skipIf(POSIX_MODE, reason='Test specific to Windows security')
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
