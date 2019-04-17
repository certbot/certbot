"""Unit test for security module."""
from certbot.compat import os
from certbot.compat import security
from certbot.tests.util import TempDirTestCase


class SecurityTest(TempDirTestCase):
    """Unit tests for security module."""
    def test_check_modes(self):
        probe = os.path.join(self.tempdir, 'probe')

        open(probe, 'w').close()

        security.chmod(probe, 0o755)

        # TODO: add assertion when check_mode is implemented
        #self.assertTrue(security.check_mode(probe, 0o755))

        security.chmod(probe, 0o700)

        # TODO: add assertion when check_mode is implemented
        #self.assertFalse(security.check_mode(probe, 0o755))
