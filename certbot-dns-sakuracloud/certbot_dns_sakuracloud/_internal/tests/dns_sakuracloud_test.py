"""Tests for certbot_dns_sakuracloud._internal.dns_sakuracloud."""
import sys
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
                        dns_test_common_lexicon.BaseLexiconDNSAuthenticatorTest):

    DOMAIN_NOT_FOUND = HTTPError(f'404 Client Error: Not Found for url: {DOMAIN}.')
    LOGIN_ERROR = HTTPError(f'401 Client Error: Unauthorized for url: {DOMAIN}.')

    def setUp(self):
        super().setUp()

        from certbot_dns_sakuracloud._internal.dns_sakuracloud import Authenticator

        path = os.path.join(self.tempdir, 'file.ini')
        dns_test_common.write(
            {"sakuracloud_api_token": API_TOKEN, "sakuracloud_api_secret": API_SECRET},
            path
        )

        self.config = mock.MagicMock(sakuracloud_credentials=path,
                                     sakuracloud_propagation_seconds=0)  # don't wait during tests

        self.auth = Authenticator(self.config, "sakuracloud")


if __name__ == "__main__":
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover
