"""Unit test for security module."""
import os

from certbot.compat import security
from certbot.tests.util import TempDirTestCase


class SecurityTest(TempDirTestCase):
    """Unit tests for security module."""
    def test_check_modes(self):
        probe = os.path.join(self.tempdir, 'probe')

        open(probe, 'w').close()

        security.apply_mode(probe, 0o755)

        self.assertTrue(security.check_mode(probe, 0o755))

        security.apply_mode(probe, 0o700)

        self.assertFalse(security.check_mode(probe, 0o755))

    def test_copy_auth(self):
        probe1 = os.path.join(self.tempdir, 'probe1')
        probe2 = os.path.join(self.tempdir, 'probe2')

        open(probe1, 'w').close()
        open(probe2, 'w').close()

        security.apply_mode(probe1, 0o700)
        security.apply_mode(probe2, 0o755)

        self.assertFalse(security.check_mode(probe2, 0o700))

        security.copy_ownership_and_apply_mode(probe1, probe2, 0o700)

        self.assertTrue(security.check_mode(probe2, 0o700))

    def test_check_modes_symlink(self):
        probe = os.path.join(self.tempdir, 'probe')
        link_abs = os.path.join(self.tempdir, 'link_abs')
        link_rel = os.path.join(self.tempdir, 'link_rel')

        open(probe, 'w').close()
        os.symlink(probe, link_abs)
        os.symlink(os.path.join('.', 'probe'), link_rel)

        security.apply_mode(probe, 0o700)

        self.assertTrue(security.check_mode(link_abs, 0o700))
        self.assertTrue(security.check_mode(link_rel, 0o700))

    def test_check_owner(self):
        probe = os.path.join(self.tempdir, 'probe')

        open(probe, 'w').close()

        self.assertTrue(security.check_owner(probe))

        security.take_ownership(probe)

        self.assertTrue(security.check_owner(probe))

    def test_current_user(self):
        current_user = security.get_current_user()

        self.assertTrue(isinstance(current_user, str))

    def test_check_permissions(self):
        probe = os.path.join(self.tempdir, 'probe')

        open(probe, 'w').close()
        security.apply_mode(probe, 0o700)

        self.assertTrue(security.check_permissions(probe, 0o700))
