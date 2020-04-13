"""Tests for certbot.plugins.dns_common_lexicon."""

import unittest

import mock

from certbot.plugins import dns_common_lexicon
from certbot.plugins import dns_test_common_lexicon


class LexiconClientTest(unittest.TestCase, dns_test_common_lexicon.BaseLexiconClientTest):

    class _FakeLexiconClient(dns_common_lexicon.LexiconClient):
        pass

    def setUp(self):
        super(LexiconClientTest, self).setUp()

        self.client = LexiconClientTest._FakeLexiconClient()
        self.provider_mock = mock.MagicMock()

        self.client.provider = self.provider_mock



if __name__ == "__main__":
    unittest.main()  # pragma: no cover
