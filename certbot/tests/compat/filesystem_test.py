"""Unit test for security module."""
import unittest

from certbot.compat import os
from certbot.compat import filesystem
from certbot.tests.util import TempDirTestCase


class FilesystemTest(TempDirTestCase):
    """Unit tests for filesystem module."""
    @unittest.skipIf(os.name != 'nt', reason='Test specific to Windows security')
    def test_user_admin_dacl_consistency(self):
        import win32security  # pylint: disable=import-error
        import win32api  # pylint: disable=import-error

        target = os.path.join(self.tempdir, 'target')
        open(target, 'w').close()

        # Set ownership of target to authenticated user
        authenticated_user, _, _ = win32security.LookupAccountName("", win32api.GetUserName())
        security_owner = win32security.GetFileSecurity(target, win32security.OWNER_SECURITY_INFORMATION)
        security_owner.SetSecurityDescriptorOwner(authenticated_user, False)
        win32security.SetFileSecurity(target, win32security.OWNER_SECURITY_INFORMATION, security_owner)

        filesystem.chmod(target, 0o700)

        security_dacl = win32security.GetFileSecurity(target, win32security.DACL_SECURITY_INFORMATION)
        dacl = security_dacl.GetSecurityDescriptorDacl()
        # We expect three ACE: one for admins, one for system, and one for the user
        self.assertEqual(dacl.GetAceCount(), 3)

        # Set ownership of target to Administrators user group
        admin_user = win32security.ConvertStringSidToSid('S-1-5-32-544')
        security_owner = win32security.GetFileSecurity(target, win32security.OWNER_SECURITY_INFORMATION)
        security_owner.SetSecurityDescriptorOwner(admin_user, False)
        win32security.SetFileSecurity(target, win32security.OWNER_SECURITY_INFORMATION, security_owner)

        filesystem.chmod(target, 0o700)

        security_dacl = win32security.GetFileSecurity(target, win32security.DACL_SECURITY_INFORMATION)
        dacl = security_dacl.GetSecurityDescriptorDacl()
        # We expect only two ACE: one for admins, one for system, since the user is also the admins group
        self.assertEqual(dacl.GetAceCount(), 2)


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
