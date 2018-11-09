"""Tests for certbot.compat."""
import os

from certbot.compat import os as os_compat
import certbot.tests.util as test_util

class OsReplaceTest(test_util.TempDirTestCase):
    """Test to ensure consistent behavior of os.rename method"""

    def test_os.rename_to_existing_file(self):
        """Ensure that os.rename will effectively rename src into dst for all platforms."""
        src = os.path.join(self.tempdir, 'src')
        dst = os.path.join(self.tempdir, 'dst')
        open(src, 'w').close()
        open(dst, 'w').close()

        # On Windows, a direct call to os.rename will fail because dst already exists.
        os_compat.rename(src, dst)

        self.assertFalse(os.path.exists(src))
        self.assertTrue(os.path.exists(dst))
