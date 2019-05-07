"""Unit test for security module."""
import unittest

from certbot.compat import os
from certbot.compat import filesystem
from certbot.tests.util import TempDirTestCase


class FilesystemTest(TempDirTestCase):
    """Unit tests for filesystem module."""
    def test_check_modes(self):
        probe = os.path.join(self.tempdir, 'probe')

        open(probe, 'w').close()

        filesystem.chmod(probe, 0o755)

        # TODO: add assertion when check_mode is implemented
        #self.assertTrue(security.check_mode(probe, 0o755))

        filesystem.chmod(probe, 0o700)

        # TODO: add assertion when check_mode is implemented
        #self.assertFalse(security.check_mode(probe, 0o755))

    @unittest.skipIf(os.name != 'nt', reason='Test specific to Windows security')
    def test_user_admin_dacl_consistency(self):
        import win32security

        normal_user = win32security.ConvertStringSidToSid('S-1-4-1')
        dacl = filesystem._generate_dacl(normal_user, 0o700)  # pylint: disable=protected-access
        # We expect two ACE: one for admins, one for system, and one for the user
        self.assertEqual(dacl.GetAceCount(), 3)

        admin_user = win32security.ConvertStringSidToSid('S-1-5-18')
        dacl = filesystem._generate_dacl(admin_user, 0o700)
        # We expect only two ACE: one for admins, one for system, since the user is also an admin
        self.assertEqual(dacl.GetAceCount(), 2)
