"""Tests for certbot_dns_cloudxns._internal.dns_cloudxns."""

import unittest

try:
    import mock
except ImportError: # pragma: no cover
    from unittest import mock # type: ignore
from requests.exceptions import HTTPError
from requests.exceptions import RequestException
import warnings

from certbot.compat import os
from certbot.plugins import dns_test_common
from certbot.plugins import dns_test_common_lexicon
from certbot.tests import util as test_util

DOMAIN_NOT_FOUND = Exception('No domain found')
GENERIC_ERROR = RequestException
LOGIN_ERROR = HTTPError('400 Client Error: ...')

API_KEY = 'foo'
SECRET = 'bar'


class AuthenticatorTest(test_util.TempDirTestCase,
                        dns_test_common_lexicon.BaseLexiconAuthenticatorTest):

    def setUp(self):
        super().setUp()

        from certbot_dns_cloudxns._internal.dns_cloudxns import Authenticator

        path = os.path.join(self.tempdir, 'file.ini')
        dns_test_common.write({"cloudxns_api_key": API_KEY, "cloudxns_secret_key": SECRET}, path)

        self.config = mock.MagicMock(cloudxns_credentials=path,
                                     cloudxns_propagation_seconds=0)  # don't wait during tests

        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", category=UserWarning)
            self.auth = Authenticator(self.config, "cloudxns")

        self.mock_client = mock.MagicMock()
        # _get_cloudxns_client | pylint: disable=protected-access
        self.auth._get_cloudxns_client = mock.MagicMock(return_value=self.mock_client)


class CloudXNSLexiconClientTest(unittest.TestCase, dns_test_common_lexicon.BaseLexiconClientTest):

    def setUp(self):
        from certbot_dns_cloudxns._internal.dns_cloudxns import _CloudXNSLexiconClient

        self.client = _CloudXNSLexiconClient(API_KEY, SECRET, 0)

        self.provider_mock = mock.MagicMock()
        self.client.provider = self.provider_mock


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
