"""Tests for certbot.compat."""
import os

from certbot import compat
import certbot.tests.util as test_util

class OsReplaceTest(test_util.TempDirTestCase):
    """Test to ensure consistent behavior of os_rename method"""

    def test_os_rename_to_existing_file(self):
        """Ensure that os_rename will effectively rename src into dst for all platforms."""
        src = os.path.join(self.tempdir, 'src')
        dst = os.path.join(self.tempdir, 'dst')
        open(src, 'w').close()
        open(dst, 'w').close()

        # On Windows, a direct call to os.rename will fail because dst already exists.
        compat.os_rename(src, dst)

        self.assertFalse(os.path.exists(src))
        self.assertTrue(os.path.exists(dst))
