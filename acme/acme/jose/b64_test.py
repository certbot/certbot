"""Tests for acme.jose.b64."""
import unittest

import six


# https://en.wikipedia.org/wiki/Base64#Examples
B64_PADDING_EXAMPLES = {
    b'any carnal pleasure.': (b'YW55IGNhcm5hbCBwbGVhc3VyZS4', b'='),
    b'any carnal pleasure': (b'YW55IGNhcm5hbCBwbGVhc3VyZQ', b'=='),
    b'any carnal pleasur': (b'YW55IGNhcm5hbCBwbGVhc3Vy', b''),
    b'any carnal pleasu': (b'YW55IGNhcm5hbCBwbGVhc3U', b'='),
    b'any carnal pleas': (b'YW55IGNhcm5hbCBwbGVhcw', b'=='),
}


B64_URL_UNSAFE_EXAMPLES = {
    six.int2byte(251) + six.int2byte(239): b'--8',
    six.int2byte(255) * 2: b'__8',
}


class B64EncodeTest(unittest.TestCase):
    """Tests for acme.jose.b64.b64encode."""

    @classmethod
    def _call(cls, data):
        from acme.jose.b64 import b64encode
        return b64encode(data)

    def test_empty(self):
        self.assertEqual(self._call(b''), b'')

    def test_unsafe_url(self):
        for text, b64 in six.iteritems(B64_URL_UNSAFE_EXAMPLES):
            self.assertEqual(self._call(text), b64)

    def test_different_paddings(self):
        for text, (b64, _) in six.iteritems(B64_PADDING_EXAMPLES):
            self.assertEqual(self._call(text), b64)

    def test_unicode_fails_with_type_error(self):
        self.assertRaises(TypeError, self._call, u'some unicode')


class B64DecodeTest(unittest.TestCase):
    """Tests for acme.jose.b64.b64decode."""

    @classmethod
    def _call(cls, data):
        from acme.jose.b64 import b64decode
        return b64decode(data)

    def test_unsafe_url(self):
        for text, b64 in six.iteritems(B64_URL_UNSAFE_EXAMPLES):
            self.assertEqual(self._call(b64), text)

    def test_input_without_padding(self):
        for text, (b64, _) in six.iteritems(B64_PADDING_EXAMPLES):
            self.assertEqual(self._call(b64), text)

    def test_input_with_padding(self):
        for text, (b64, pad) in six.iteritems(B64_PADDING_EXAMPLES):
            self.assertEqual(self._call(b64 + pad), text)

    def test_unicode_with_ascii(self):
        self.assertEqual(self._call(u'YQ'), b'a')

    def test_non_ascii_unicode_fails(self):
        self.assertRaises(ValueError, self._call, u'\u0105')

    def test_type_error_no_unicode_or_bytes(self):
        self.assertRaises(TypeError, self._call, object())


if __name__ == '__main__':
    unittest.main()  # pragma: no cover
