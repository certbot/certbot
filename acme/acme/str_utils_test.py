"""Tests for acme.str_utils."""
import unittest

import six


class ForceTextTest(unittest.TestCase):
    """Test for acme.str_utils.force_text."""

    def _call(self, item):
        from acme.str_utils import force_text
        return force_text(item)

    def test_force_text(self):
        uni_str = u"\xf6"
        byte_str = b"bytes"
        str_str = "str"
        self.assertTrue(isinstance(self._call(uni_str), six.text_type))
        self.assertTrue(isinstance(self._call(byte_str), six.text_type))
        self.assertTrue(isinstance(self._call(str_str), six.text_type))

    def test_force_text_failure(self):
        self.assertRaises(TypeError, self._call, 2)


class ForceBytesTest(unittest.TestCase):
    """Test for acme.str_utils.force_bytes."""

    def _call(self, item):
        from acme.str_utils import force_bytes
        return force_bytes(item)

    def test_force_bytes(self):
        uni_str = u"\xf6"
        byte_str = b"bytes"
        str_str = "str"
        self.assertTrue(isinstance(self._call(uni_str), six.binary_type))
        self.assertTrue(isinstance(self._call(byte_str), six.binary_type))
        self.assertTrue(isinstance(self._call(str_str), six.binary_type))

    def test_force_bytes_failure(self):
        self.assertRaises(TypeError, self._call, 2)


class ForceStrTest(unittest.TestCase):
    """Test for acme.str_utils.force_str."""

    def _call(self, item):
        from acme.str_utils import force_str
        return force_str(item)

    def test_force_bytes(self):
        uni_str = u"\xf6"
        byte_str = b"bytes"
        str_str = "str"
        self.assertTrue(isinstance(self._call(uni_str), str))
        self.assertTrue(isinstance(self._call(byte_str), str))
        self.assertTrue(isinstance(self._call(str_str), str))

    def test_force_bytes_failure(self):
        self.assertRaises(TypeError, self._call, 2)


if __name__ == '__main__':
    unittest.main()  # pragma: no cover
