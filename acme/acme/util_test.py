"""Tests for acme.util."""
import unittest

from acme import errors


class MapKeysTest(unittest.TestCase):
    """Tests for acme.util.map_keys."""

    def test_it(self):
        from acme.util import map_keys
        self.assertEqual({'a': 'b', 'c': 'd'},
                         map_keys({'a': 'b', 'c': 'd'}, lambda key: key))
        self.assertEqual({2: 2, 4: 4}, map_keys({1: 2, 3: 4}, lambda x: x + 1))


class ActivateTest(unittest.TestCase):
    """Tests for acme.util.activate."""

    @classmethod
    def _call(cls, *args, **kwargs):
        from acme.util import activate
        return activate(*args, **kwargs)

    def test_failure(self):
        self.assertRaises(errors.DependencyError, self._call, 'acme>99.0.0')

    def test_success(self):
        self._call('acme')
        import acme as unused_acme


if __name__ == '__main__':
    unittest.main()  # pragma: no cover
