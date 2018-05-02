import mock
import sys
import unittest


class MagicTypingTest(unittest.TestCase):
    """Tests for acme.magic_typing."""
    def setUp(self):
        super(MagicTypingTest, self).setUp()
        if 'acme.magic_typing' in sys.modules:
            del sys.modules['acme.magic_typing']

    def test_import_success(self):
        typing_class_mock = mock.MagicMock()
        sys.modules['typing'] = typing_class_mock
        from acme.magic_typing import Text
        self.assertEqual(sys.modules['acme.magic_typing'], typing_class_mock)

    def test_import_failure(self):
        sys.modules['typing'] = None
        from acme.magic_typing import Text
        self.assertTrue(Text is None)


if __name__ == '__main__':
    unittest.main()  # pragma: no cover
