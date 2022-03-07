"""Tests for certbot_dns_dnsmadeeasy._internal.dns_dnsmadeeasy."""

import unittest

try:
    import mock
except ImportError: # pragma: no cover
    from unittest import mock # type: ignore
from requests.exceptions import HTTPError

from certbot.compat import os
from certbot.plugins import dns_test_common
from certbot.plugins import dns_test_common_lexicon
from certbot.plugins.dns_test_common import DOMAIN
from certbot.tests import util as test_util

API_KEY = 'foo'
SECRET_KEY = 'bar'


class AuthenticatorTest(test_util.TempDirTestCase,
                        dns_test_common_lexicon.BaseLexiconAuthenticatorTest):

    def setUp(self):
        super().setUp()

        from certbot_dns_dnsmadeeasy._internal.dns_dnsmadeeasy import Authenticator

        path = os.path.join(self.tempdir, 'file.ini')
        dns_test_common.write({"dnsmadeeasy_api_key": API_KEY,
                               "dnsmadeeasy_secret_key": SECRET_KEY},
                              path)

        self.config = mock.MagicMock(dnsmadeeasy_credentials=path,
                                     dnsmadeeasy_propagation_seconds=0)  # don't wait during tests

        self.auth = Authenticator(self.config, "dnsmadeeasy")

        self.mock_client = mock.MagicMock()
        # _get_dnsmadeeasy_client | pylint: disable=protected-access
        self.auth._get_dnsmadeeasy_client = mock.MagicMock(return_value=self.mock_client)


class DNSMadeEasyLexiconClientTest(unittest.TestCase,
                                   dns_test_common_lexicon.BaseLexiconClientTest):
    DOMAIN_NOT_FOUND = HTTPError(f'404 Client Error: Not Found for url: {DOMAIN}.')
    LOGIN_ERROR = HTTPError(f'403 Client Error: Forbidden for url: {DOMAIN}.')

    def setUp(self):
        from certbot_dns_dnsmadeeasy._internal.dns_dnsmadeeasy import _DNSMadeEasyLexiconClient

        self.client = _DNSMadeEasyLexiconClient(API_KEY, SECRET_KEY, 0)

        self.provider_mock = mock.MagicMock()
        self.client.provider = self.provider_mock


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
