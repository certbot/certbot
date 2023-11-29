"""Tests for certbot_dns_nsone._internal.dns_nsone."""
import sys
from unittest import mock

import pytest
from requests import Response
from requests.exceptions import HTTPError

from certbot.compat import os
from certbot.plugins import dns_test_common
from certbot.plugins import dns_test_common_lexicon
from certbot.plugins.dns_test_common import DOMAIN
from certbot.tests import util as test_util

API_KEY = 'foo'


class AuthenticatorTest(test_util.TempDirTestCase,
                        dns_test_common_lexicon.BaseLexiconDNSAuthenticatorTest):

    DOMAIN_NOT_FOUND = HTTPError(f'404 Client Error: Not Found for url: {DOMAIN}.', response=Response())
    LOGIN_ERROR = HTTPError(f'401 Client Error: Unauthorized for url: {DOMAIN}.', response=Response())

    def setUp(self):
        super().setUp()

        from certbot_dns_nsone._internal.dns_nsone import Authenticator

        path = os.path.join(self.tempdir, 'file.ini')
        dns_test_common.write({"nsone_api_key": API_KEY}, path)

        self.config = mock.MagicMock(nsone_credentials=path,
                                     nsone_propagation_seconds=0)  # don't wait during tests

        self.auth = Authenticator(self.config, "nsone")


if __name__ == "__main__":
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover
