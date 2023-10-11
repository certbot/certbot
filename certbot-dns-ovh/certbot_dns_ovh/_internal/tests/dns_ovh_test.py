"""Tests for certbot_dns_ovh._internal.dns_ovh."""
from unittest import mock
import sys

import pytest
from requests import Response
from requests.exceptions import HTTPError

from certbot.compat import os
from certbot.plugins import dns_test_common
from certbot.plugins import dns_test_common_lexicon
from certbot.tests import util as test_util

ENDPOINT = 'ovh-eu'
APPLICATION_KEY = 'foo'
APPLICATION_SECRET = 'bar'
CONSUMER_KEY = 'spam'


class AuthenticatorTest(test_util.TempDirTestCase,
                        dns_test_common_lexicon.BaseLexiconDNSAuthenticatorTest):

    DOMAIN_NOT_FOUND = Exception('Domain example.com not found')
    LOGIN_ERROR = HTTPError('403 Client Error: Forbidden for url: https://eu.api.ovh.com/1.0/...', response=Response())

    def setUp(self):
        super().setUp()

        from certbot_dns_ovh._internal.dns_ovh import Authenticator

        path = os.path.join(self.tempdir, 'file.ini')
        credentials = {
            "ovh_endpoint": ENDPOINT,
            "ovh_application_key": APPLICATION_KEY,
            "ovh_application_secret": APPLICATION_SECRET,
            "ovh_consumer_key": CONSUMER_KEY,
        }
        dns_test_common.write(credentials, path)

        self.config = mock.MagicMock(ovh_credentials=path,
                                     ovh_propagation_seconds=0)  # don't wait during tests

        self.auth = Authenticator(self.config, 'ovh')


if __name__ == "__main__":
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover
