"""Unit test for security module."""
import unittest

from certbot.compat import os
from certbot.compat import filesystem
from certbot.tests.util import TempDirTestCase


@unittest.skipIf(os.name != 'nt', reason='Test specific to Windows security')
class WindowsChmodTests(TempDirTestCase):
    """Unit tests for Windows chmod function in filesystem module"""
    def test_symlink_resolution(self):
        probe_path = _create_probe(self.tempdir)  # This is 0o744 by default

        link_path = os.path.join(self.tempdir, 'link')
        os.symlink(probe_path, link_path)

        ref_dacl_probe = _get_security_dacl(probe_path).GetSecurityDescriptorDacl()
        ref_dacl_link = _get_security_dacl(link_path).GetSecurityDescriptorDacl()

        # Removing the rights for `all`, we have at least one ACL less than in the case of 0o744.
        filesystem.chmod(link_path, 0o700)

        # Assert the real file is impacted, not the link.
        cur_dacl_probe = _get_security_dacl(probe_path).GetSecurityDescriptorDacl()
        cur_dacl_link = _get_security_dacl(link_path).GetSecurityDescriptorDacl()
        self.assertFalse(filesystem._compare_dacls(ref_dacl_probe, cur_dacl_probe))  # pylint: disable=protected-access
        self.assertTrue(filesystem._compare_dacls(ref_dacl_link, cur_dacl_link))  # pylint: disable=protected-access

    def test_world_permission(self):
        import win32security  # pylint: disable=import-error
        probe_path = _create_probe(self.tempdir)

        everybody = win32security.ConvertStringSidToSid('S-1-1-0')

        filesystem.chmod(probe_path, 0o700)
        dacl = _get_security_dacl(probe_path).GetSecurityDescriptorDacl()

        self.assertFalse([dacl.GetAce(index) for index in range(0, dacl.GetAceCount())
                          if dacl.GetAce(index)[2] == everybody])

        filesystem.chmod(probe_path, 0o704)
        dacl = _get_security_dacl(probe_path).GetSecurityDescriptorDacl()

        self.assertTrue([dacl.GetAce(index) for index in range(0, dacl.GetAceCount())
                         if dacl.GetAce(index)[2] == everybody])

    def test_group_permissions_noop(self):
        probe_path = _create_probe(self.tempdir)

        filesystem.chmod(probe_path, 0o700)
        ref_dacl_probe = _get_security_dacl(probe_path).GetSecurityDescriptorDacl()

        filesystem.chmod(probe_path, 0o740)
        cur_dacl_probe = _get_security_dacl(probe_path).GetSecurityDescriptorDacl()

        self.assertTrue(filesystem._compare_dacls(ref_dacl_probe, cur_dacl_probe))  # pylint: disable=protected-access

    def test_admin_permissions(self):
        import win32security  # pylint: disable=import-error
        probe_path = _create_probe(self.tempdir)

        system = win32security.ConvertStringSidToSid('S-1-5-18')
        admins = win32security.ConvertStringSidToSid('S-1-5-32-544')

        filesystem.chmod(probe_path, 0o700)
        dacl = _get_security_dacl(probe_path).GetSecurityDescriptorDacl()

        self.assertTrue([dacl.GetAce(index) for index in range(0, dacl.GetAceCount())
                         if dacl.GetAce(index)[2] == system])
        self.assertTrue([dacl.GetAce(index) for index in range(0, dacl.GetAceCount())
                         if dacl.GetAce(index)[2] == admins])

    def test_read_flag(self):
        import ntsecuritycon  # pylint: disable=import-error
        self._test_flag(4, ntsecuritycon.FILE_GENERIC_READ)

    def test_execute_flag(self):
        import ntsecuritycon  # pylint: disable=import-error
        self._test_flag(1, ntsecuritycon.FILE_GENERIC_EXECUTE)

    def test_write_flag(self):
        import ntsecuritycon  # pylint: disable=import-error
        self._test_flag(2, (ntsecuritycon.FILE_ALL_ACCESS
                            ^ ntsecuritycon.FILE_GENERIC_READ
                            ^ ntsecuritycon.FILE_GENERIC_EXECUTE
                            ^ 512))

    def test_full_flag(self):
        import ntsecuritycon  # pylint: disable=import-error
        self._test_flag(7, (ntsecuritycon.FILE_ALL_ACCESS
                            ^ 512))

    def _test_flag(self, everyone_mode, windows_flag):
        # Note that flag is tested against `everyone`, not `user`, because practically these unit
        # tests are executed with admin privilege, so current user is effectively the admins group,
        # and so will always have all rights.
        import win32security  # pylint: disable=import-error
        probe_path = _create_probe(self.tempdir)

        filesystem.chmod(probe_path, 0o700 + everyone_mode)
        dacl = _get_security_dacl(probe_path).GetSecurityDescriptorDacl()
        everybody = win32security.ConvertStringSidToSid('S-1-1-0')

        acls_user = [dacl.GetAce(index) for index in range(0, dacl.GetAceCount())
                     if dacl.GetAce(index)[2] == everybody]

        self.assertEqual(len(acls_user), 1)

        acl_user = acls_user[0]

        self.assertEqual(acl_user[1], windows_flag)

    def test_user_admin_dacl_consistency(self):
        import win32security  # pylint: disable=import-error
        import win32api  # pylint: disable=import-error

        probe_path = _create_probe(self.tempdir)

        # Set ownership of target to authenticated user
        authenticated_user, _, _ = win32security.LookupAccountName("", win32api.GetUserName())
        security_owner = _get_security_owner(probe_path)
        _set_owner(probe_path, security_owner, authenticated_user)

        filesystem.chmod(probe_path, 0o700)

        security_dacl = _get_security_dacl(probe_path)
        # We expect three ACE: one for admins, one for system, and one for the user
        self.assertEqual(security_dacl.GetSecurityDescriptorDacl().GetAceCount(), 3)

        # Set ownership of target to Administrators user group
        admin_user = win32security.ConvertStringSidToSid('S-1-5-32-544')
        security_owner = _get_security_owner(probe_path)
        _set_owner(probe_path, security_owner, admin_user)

        filesystem.chmod(probe_path, 0o700)

        security_dacl = _get_security_dacl(probe_path)
        # We expect only two ACE: one for admins, one for system,
        # since the user is also the admins group
        self.assertEqual(security_dacl.GetSecurityDescriptorDacl().GetAceCount(), 2)


def _get_security_dacl(target):
    import win32security  # pylint: disable=import-error
    return win32security.GetFileSecurity(target, win32security.DACL_SECURITY_INFORMATION)


def _get_security_owner(target):
    import win32security  # pylint: disable=import-error
    return win32security.GetFileSecurity(target, win32security.OWNER_SECURITY_INFORMATION)


def _set_owner(target, security_owner, user):
    import win32security  # pylint: disable=import-error
    security_owner.SetSecurityDescriptorOwner(user, False)
    win32security.SetFileSecurity(
        target, win32security.OWNER_SECURITY_INFORMATION, security_owner)


def _create_probe(tempdir):
    probe_path = os.path.join(tempdir, 'probe')
    open(probe_path, 'w').close()
    return probe_path


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
