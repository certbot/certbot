"""Tests for certbot_dns_godaddy.dns_godaddy."""

import unittest

import mock

from requests.exceptions import HTTPError

from certbot.compat import os
from certbot.plugins import dns_test_common
from certbot.plugins import dns_test_common_lexicon
from certbot.plugins.dns_test_common import DOMAIN
from certbot.tests import util as test_util
from certbot_dns_godaddy.dns_godaddy import Authenticator

API_KEY = 'a-token'
API_SECRET = 'secret'

class AuthenticatorTest(test_util.TempDirTestCase,
                        dns_test_common_lexicon.BaseLexiconAuthenticatorTest):

    def setUp(self):
        super(AuthenticatorTest, self).setUp()

        path = os.path.join(self.tempdir, 'file.ini')
        dns_test_common.write({"godaddy_key": API_KEY, 'godaddy_secret': API_SECRET}, path)

        self.config = mock.MagicMock(godaddy_credentials=path,
                                     godaddy_propagation_seconds=0)  # don't wait during tests

        self.auth = Authenticator(self.config, "godaddy")

        self.mock_client = mock.MagicMock()
        # _get_godaddy_client | pylint: disable=protected-access
        self.auth._get_godaddy_client = mock.MagicMock(return_value=self.mock_client)

class GodaddyLexiconClientTest(unittest.TestCase, dns_test_common_lexicon.BaseLexiconClientTest):
    DOMAIN_NOT_FOUND = HTTPError('404 Client Error: Not Found for url: {0}.'.format(DOMAIN))
    LOGIN_ERROR = HTTPError('401 Client Error: Unauthorized for url: {0}.'.format(DOMAIN))

    def setUp(self):
        from certbot_dns_godaddy.dns_godaddy import _GodaddyLexiconClient

        self.client = _GodaddyLexiconClient(API_KEY, API_SECRET)

        self.provider_mock = mock.MagicMock()
        self.client.provider = self.provider_mock

if __name__ == "__main__":
    unittest.main()  # pragma: no cover
