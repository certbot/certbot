"""Tests for letsencrypt.client.le_util."""
import os
import shutil
import tempfile
import unittest


class MakeOrVerifyDirTest(unittest.TestCase):
    """Tests for letsencrypt.client.le_util.make_or_verify_dir.

    Note that it is not possible to test for a wrong directory owner,
    as this testing script would have to be run as root.

    """

    def setUp(self):
        self.root_path = tempfile.mkdtemp()
        self.path = os.path.join(self.root_path, 'foo')
        os.mkdir(self.path, 0400)

        self.uid = os.getuid()

    def tearDown(self):
        shutil.rmtree(self.root_path, ignore_errors=True)

    def _call(self, directory, mode):
        from letsencrypt.client.le_util import make_or_verify_dir
        return make_or_verify_dir(directory, mode, self.uid)

    def test_creates_dir_when_missing(self):
        path = os.path.join(self.root_path, 'bar')
        self._call(path, 0650)
        self.assertTrue(os.path.isdir(path))
        # TODO: check mode

    def test_existing_correct_mode_does_not_fail(self):
        self._call(self.path, 0400)
        # TODO: check mode

    def test_existing_wrong_mode_fails(self):
        self.assertRaises(Exception, self._call, self.path, 0600)


class CheckPermissionsTest(unittest.TestCase):
    """Tests for letsencrypt.client.le_util.check_permissions.

    Note that it is not possible to test for a wrong file owner,
    as this testing script would have to be run as root.

    """

    def setUp(self):
        _, self.path = tempfile.mkstemp()
        self.uid = os.getuid()

    def tearDown(self):
        os.remove(self.path)

    def _call(self, mode):
        from letsencrypt.client.le_util import check_permissions
        return check_permissions(self.path, mode, self.uid)

    def test_ok_mode(self):
        os.chmod(self.path, 0600)
        self.assertTrue(self._call(0600))

    def test_wrong_mode(self):
        os.chmod(self.path, 0400)
        self.assertFalse(self._call(0600))


class JOSEB64EncodeTest(unittest.TestCase):
    """Tests for letsencrypt.client.le_util.jose_b64encode."""

    def _call(self, data, encoding):
        from letsencrypt.client.le_util import jose_b64encode
        return jose_b64encode(data, encoding)

    def test_without_encoding(self):
        self.assertEqual(self._call('foo', None), 'Zm9v')

    def test_with_encoding(self):
        self.assertEqual(self._call(u'\u0105', 'utf-8'), 'xIU')


class JOSEB64DecodeTest(unittest.TestCase):
    """Tests for letsencrypt.client.le_util.jose_b64decode."""

    def _call(self, jose_b64_string, decoding):
        from letsencrypt.client.le_util import jose_b64decode
        return jose_b64decode(jose_b64_string, decoding)

    def test_without_decoding(self):
        self.assertEqual(self._call('Zm9v=', None), 'foo')

    def test_with_encoding(self):
        self.assertEqual(self._call('xIU=', 'utf-8'), u'\u0105')

    def test_fills_padding(self):
        self.assertEqual(self._call('Zm9v', None), 'foo')


if __name__ == '__main__':
    unittest.main()
