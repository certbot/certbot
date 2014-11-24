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


# https://en.wikipedia.org/wiki/Base64#Examples
JOSE_B64_PADDING_EXAMPLES = {
    'any carnal pleasure.': ('YW55IGNhcm5hbCBwbGVhc3VyZS4', '='),
    'any carnal pleasure': ('YW55IGNhcm5hbCBwbGVhc3VyZQ', '=='),
    'any carnal pleasur': ('YW55IGNhcm5hbCBwbGVhc3Vy', ''),
    'any carnal pleasu': ('YW55IGNhcm5hbCBwbGVhc3U', '='),
    'any carnal pleas': ('YW55IGNhcm5hbCBwbGVhcw', '=='),
}


B64_URL_UNSAFE_EXAMPLES = {
    chr(251) + chr(239): '--8',
    chr(255) * 2: '__8',
}


class JOSEB64EncodeTest(unittest.TestCase):
    """Tests for letsencrypt.client.le_util.jose_b64encode."""

    def _call(self, data):
        from letsencrypt.client.le_util import jose_b64encode
        return jose_b64encode(data)

    def test_unsafe_url(self):
        for text, b64 in B64_URL_UNSAFE_EXAMPLES.iteritems():
            self.assertEqual(self._call(text), b64)

    def test_different_paddings(self):
        for text, (b64, _) in JOSE_B64_PADDING_EXAMPLES.iteritems():
            self.assertEqual(self._call(text), b64)

    def test_unicode_fails_with_type_error(self):
        self.assertRaises(TypeError, self._call, u'some unicode')


class JOSEB64DecodeTest(unittest.TestCase):
    """Tests for letsencrypt.client.le_util.jose_b64decode."""

    def _call(self, data):
        from letsencrypt.client.le_util import jose_b64decode
        return jose_b64decode(data)

    def test_unsafe_url(self):
        for text, b64 in B64_URL_UNSAFE_EXAMPLES.iteritems():
            self.assertEqual(self._call(b64), text)

    def test_input_without_padding(self):
        for text, (b64, _) in JOSE_B64_PADDING_EXAMPLES.iteritems():
            self.assertEqual(self._call(b64), text)

    def test_input_with_padding(self):
        for text, (b64, pad) in JOSE_B64_PADDING_EXAMPLES.iteritems():
            self.assertEqual(self._call(b64 + pad), text)

    def test_unicode_with_ascii(self):
        self.assertEqual(self._call(u'YQ'), 'a')

    def test_non_ascii_unicode_fails(self):
        self.assertRaises(ValueError, self._call, u'\u0105')


if __name__ == '__main__':
    unittest.main()
