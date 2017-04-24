"""Tests for certbot.plugins.dns_dnsimple."""

import mock
import unittest

from requests.exceptions import HTTPError

from certbot.plugins import dns_test_common

TOKEN = 'foo'


class AuthenticatorTest(unittest.TestCase, dns_test_common.BaseLexiconAuthenticatorTest):

    def setUp(self):
        from certbot.plugins.dns_dnsimple import Authenticator
        self.config = mock.MagicMock(dnsimple_token=TOKEN,
                                     dnsimple_propagation_seconds=0)  # don't wait during tests

        self.auth = Authenticator(self.config, "dnsimple")

        self.mock_client = mock.MagicMock()
        # _get_dnsimple_client | pylint: disable=protected-access
        self.auth._get_dnsimple_client = mock.MagicMock(return_value=self.mock_client)


class DNSimpleLexiconClientTest(unittest.TestCase, dns_test_common.BaseLexiconClientTest):

    LOGIN_ERROR = HTTPError('401 Client Error: Unauthorized for url: ...')

    def setUp(self):
        from certbot.plugins.dns_dnsimple import _DNSimpleLexiconClient

        self.client = _DNSimpleLexiconClient(TOKEN, 0)

        self.provider_mock = mock.MagicMock()
        self.client.provider = self.provider_mock


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
