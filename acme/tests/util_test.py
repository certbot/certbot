"""Tests for acme.util."""
import sys
import unittest

import pytest


class MapKeysTest(unittest.TestCase):
    """Tests for acme.util.map_keys."""

    def test_it(self):
        from acme.util import map_keys
        self.assertEqual({'a': 'b', 'c': 'd'},
                         map_keys({'a': 'b', 'c': 'd'}, lambda key: key))
        self.assertEqual({2: 2, 4: 4}, map_keys({1: 2, 3: 4}, lambda x: x + 1))


if __name__ == '__main__':
    sys.exit(pytest.main([__file__]))  # pragma: no cover
