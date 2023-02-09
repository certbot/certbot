"""Tests for certbot_dns_gehirn._internal.dns_gehirn."""

import sys
import unittest
from unittest import mock

import pytest
from requests.exceptions import HTTPError

from certbot.compat import os
from certbot.plugins import dns_test_common
from certbot.plugins import dns_test_common_lexicon
from certbot.plugins.dns_test_common import DOMAIN
from certbot.tests import util as test_util

API_TOKEN = '00000000-0000-0000-0000-000000000000'
API_SECRET = 'MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAw'

class AuthenticatorTest(test_util.TempDirTestCase,
                        dns_test_common_lexicon.BaseLexiconAuthenticatorTest):

    def setUp(self):
        super().setUp()

        from certbot_dns_gehirn._internal.dns_gehirn import Authenticator

        path = os.path.join(self.tempdir, 'file.ini')
        dns_test_common.write(
            {"gehirn_api_token": API_TOKEN, "gehirn_api_secret": API_SECRET},
            path
        )

        self.config = mock.MagicMock(gehirn_credentials=path,
                                     gehirn_propagation_seconds=0)  # don't wait during tests

        self.auth = Authenticator(self.config, "gehirn")

        self.mock_client = mock.MagicMock()
        # _get_gehirn_client | pylint: disable=protected-access
        self.auth._get_gehirn_client = mock.MagicMock(return_value=self.mock_client)


class GehirnLexiconClientTest(unittest.TestCase, dns_test_common_lexicon.BaseLexiconClientTest):
    DOMAIN_NOT_FOUND = HTTPError('404 Client Error: Not Found for url: {0}.'.format(DOMAIN))
    LOGIN_ERROR = HTTPError('401 Client Error: Unauthorized for url: {0}.'.format(DOMAIN))

    def setUp(self):
        from certbot_dns_gehirn._internal.dns_gehirn import _GehirnLexiconClient

        self.client = _GehirnLexiconClient(API_TOKEN, API_SECRET, 0)

        self.provider_mock = mock.MagicMock()
        self.client.provider = self.provider_mock


if __name__ == "__main__":
    sys.exit(pytest.main([__file__]))  # pragma: no cover
