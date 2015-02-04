"""Tests for letsencrypt.client.display."""
import unittest


class GenHTTPSNamesTest(unittest.TestCase):
    """Tests for letsencrypt.client.display.gen_https_names."""

    @classmethod
    def _call(cls, domains):
        from letsencrypt.client.display import gen_https_names
        return gen_https_names(domains)

    def test_none_returns_empty_str(self):
        self.assertEqual("", self._call([]))

    def test_one_domain_no_comma(self):
        self.assertEqual("https://example.com", self._call(["example.com"]))

    def test_multiple_sep_by_comma(self):
        self.assertEqual(
            "https://a.com, https://b.com, https://c.com",
            self._call(["a.com", "b.com", "c.com"]))


if __name__ == "__main__":
    unittest.main()
