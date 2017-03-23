"""Tests for certbot.plugins.dns_common."""

import unittest

from certbot.plugins import dns_common


class DomainNameGuessTest(unittest.TestCase):

    def test_simple_case(self):
        self.assertTrue(
            'example.com' in
            dns_common.base_domain_name_guesses("example.com")
        )

    def test_sub_domain(self):
        self.assertTrue(
            'example.com' in
            dns_common.base_domain_name_guesses("foo.bar.baz.example.com")
        )

    def test_second_level_domain(self):
        self.assertTrue(
            'example.co.uk' in
            dns_common.base_domain_name_guesses("foo.bar.baz.example.co.uk")
        )


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
