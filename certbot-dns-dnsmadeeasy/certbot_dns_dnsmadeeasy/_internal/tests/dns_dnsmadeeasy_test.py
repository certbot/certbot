"""Tests for certbot_dns_dnsmadeeasy._internal.dns_dnsmadeeasy."""

import sys
from unittest import mock

import pytest
from requests.exceptions import HTTPError

from certbot.compat import os
from certbot.plugins import dns_test_common
from certbot.plugins import dns_test_common_lexicon
from certbot.plugins.dns_test_common import DOMAIN
from certbot.tests import util as test_util

API_KEY = 'foo'
SECRET_KEY = 'bar'


class AuthenticatorTest(test_util.TempDirTestCase,
                        dns_test_common_lexicon.BaseLexiconDNSAuthenticatorTest):

    DOMAIN_NOT_FOUND = HTTPError(f'404 Client Error: Not Found for url: {DOMAIN}.')
    LOGIN_ERROR = HTTPError(f'403 Client Error: Forbidden for url: {DOMAIN}.')

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


if __name__ == "__main__":
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover
