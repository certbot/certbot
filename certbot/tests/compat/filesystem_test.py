"""Tests for certbot.compat.filesystem"""
import certbot.tests.util as test_util
from certbot.compat import os
from certbot.compat import filesystem


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
