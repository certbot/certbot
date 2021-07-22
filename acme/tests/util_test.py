"""Tests for acme.util."""
import unittest


class MapKeysTest(unittest.TestCase):
    """Tests for acme.util.map_keys."""

    def test_it(self):
        from acme.util import map_keys
        self.assertEqual({'a': 'b', 'c': 'd'},
                         map_keys({'a': 'b', 'c': 'd'}, lambda key: key))
        self.assertEqual({2: 2, 4: 4}, map_keys({1: 2, 3: 4}, lambda x: x + 1))


if __name__ == '__main__':
    unittest.main()  # pragma: no cover

class IpCheckTest(unittest.TestCase):
    def test_is_ip(self):
        from acme.util import is_ip
        self.assertTrue(is_ip("127.0.0.1"))
        self.assertFalse(is_ip("baa.foo.exemple"))
        self.assertTrue(is_ip("fe23:23bd::daaf"))
