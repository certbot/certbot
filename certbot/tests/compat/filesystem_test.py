"""Unit test for security module."""
import unittest

from certbot.compat import os
from certbot.compat import filesystem
from certbot.tests.util import TempDirTestCase


class SecurityTest(TempDirTestCase):
    """Unit tests for security module."""
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
        dacl = filesystem._generate_dacl(normal_user, 0o700)
        # We expect two ACE: one for admins, one for the user
        self.assertEqual(dacl.GetAceCount(), 2)

        admin_user = win32security.ConvertStringSidToSid('S-1-5-18')
        dacl = filesystem._generate_dacl(admin_user, 0o700)
        # Now we expect only ACE, the one for admins, since the user is also an admin
        self.assertEqual(dacl.GetAceCount(), 1)
