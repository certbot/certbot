"""Tests for certbot_dns_dnsimple._internal.dns_dnsimple."""

import unittest
from unittest import mock

from requests.exceptions import HTTPError

from certbot.compat import os
from certbot.plugins import dns_test_common
from certbot.plugins import dns_test_common_lexicon
from certbot.tests import util as test_util

TOKEN = 'foo'


class AuthenticatorTest(test_util.TempDirTestCase,
                        dns_test_common_lexicon.BaseLexiconAuthenticatorTest):

    def setUp(self):
        super().setUp()

        from certbot_dns_dnsimple._internal.dns_dnsimple import Authenticator

        path = os.path.join(self.tempdir, 'file.ini')
        dns_test_common.write({"dnsimple_token": TOKEN}, path)

        self.config = mock.MagicMock(dnsimple_credentials=path,
                                     dnsimple_propagation_seconds=0)  # don't wait during tests

        self.auth = Authenticator(self.config, "dnsimple")

        self.mock_client = mock.MagicMock()
        # _get_dnsimple_client | pylint: disable=protected-access
        self.auth._get_dnsimple_client = mock.MagicMock(return_value=self.mock_client)


class DNSimpleLexiconClientTest(unittest.TestCase, dns_test_common_lexicon.BaseLexiconClientTest):

    LOGIN_ERROR = HTTPError('401 Client Error: Unauthorized for url: ...')

    def setUp(self):
        from certbot_dns_dnsimple._internal.dns_dnsimple import _DNSimpleLexiconClient

        self.client = _DNSimpleLexiconClient(TOKEN, 0)

        self.provider_mock = mock.MagicMock()
        self.client.provider = self.provider_mock


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
