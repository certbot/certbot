"""Tests for acme.util."""
import unittest

import pytest
import six

# turns all ResourceWarnings into errors for this module
if six.PY3:
    pytestmark = pytest.mark.filterwarnings("ignore::ResourceWarning") # pragma: no cover


class MapKeysTest(unittest.TestCase):
    """Tests for acme.util.map_keys."""

    def test_it(self):
        from acme.util import map_keys
        self.assertEqual({'a': 'b', 'c': 'd'},
                         map_keys({'a': 'b', 'c': 'd'}, lambda key: key))
        self.assertEqual({2: 2, 4: 4}, map_keys({1: 2, 3: 4}, lambda x: x + 1))


if __name__ == '__main__':
    unittest.main()  # pragma: no cover
