"""Tests for letsencrypt.acme.jose.b64."""
import unittest


# https://en.wikipedia.org/wiki/Base64#Examples
B64_PADDING_EXAMPLES = {
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


class B64EncodeTest(unittest.TestCase):
    """Tests for letsencrypt.acme.jose.b64.b64encode."""

    @classmethod
    def _call(cls, data):
        from letsencrypt.acme.jose.b64 import b64encode
        return b64encode(data)

    def test_unsafe_url(self):
        for text, b64 in B64_URL_UNSAFE_EXAMPLES.iteritems():
            self.assertEqual(self._call(text), b64)

    def test_different_paddings(self):
        for text, (b64, _) in B64_PADDING_EXAMPLES.iteritems():
            self.assertEqual(self._call(text), b64)

    def test_unicode_fails_with_type_error(self):
        self.assertRaises(TypeError, self._call, u'some unicode')


class B64DecodeTest(unittest.TestCase):
    """Tests for letsencrypt.acme.jose.b64.b64decode."""

    @classmethod
    def _call(cls, data):
        from letsencrypt.acme.jose.b64 import b64decode
        return b64decode(data)

    def test_unsafe_url(self):
        for text, b64 in B64_URL_UNSAFE_EXAMPLES.iteritems():
            self.assertEqual(self._call(b64), text)

    def test_input_without_padding(self):
        for text, (b64, _) in B64_PADDING_EXAMPLES.iteritems():
            self.assertEqual(self._call(b64), text)

    def test_input_with_padding(self):
        for text, (b64, pad) in B64_PADDING_EXAMPLES.iteritems():
            self.assertEqual(self._call(b64 + pad), text)

    def test_unicode_with_ascii(self):
        self.assertEqual(self._call(u'YQ'), 'a')

    def test_non_ascii_unicode_fails(self):
        self.assertRaises(ValueError, self._call, u'\u0105')

    def test_type_error_no_unicode_or_str(self):
        self.assertRaises(TypeError, self._call, object())


if __name__ == '__main__':
    unittest.main()
