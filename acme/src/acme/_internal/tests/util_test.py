"""Tests for acme.util."""
import sys
import unittest

import pytest


def test_it():
    from acme.util import map_keys
    assert {'a': 'b', 'c': 'd'} == \
                     map_keys({'a': 'b', 'c': 'd'}, lambda key: key)
    assert {2: 2, 4: 4} == map_keys({1: 2, 3: 4}, lambda x: x + 1)


class IsWildcardDomainTest(unittest.TestCase):
    """Tests for is_wildcard_domain."""

    def setUp(self):
        self.wildcard = u"*.example.org"
        self.no_wildcard = u"example.org"

    def _call(self, domain):
        from acme.util import is_wildcard_domain
        return is_wildcard_domain(domain)

    def test_no_wildcard(self):
        assert not self._call(self.no_wildcard)
        assert not self._call(self.no_wildcard.encode())

    def test_wildcard(self):
        assert self._call(self.wildcard)
        assert self._call(self.wildcard.encode())


if __name__ == '__main__':
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover
