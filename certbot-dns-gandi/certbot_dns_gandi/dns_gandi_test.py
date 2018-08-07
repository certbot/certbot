"""Tests for certbot_dns_gandi.dns_gandi."""

import os
import unittest

import mock
from requests.exceptions import HTTPError

from certbot.plugins import dns_test_common
from certbot.plugins import dns_test_common_lexicon
from certbot.plugins.dns_test_common import DOMAIN
from certbot.tests import util as test_util

TOKEN = 'MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAw'

class AuthenticatorTest(test_util.TempDirTestCase,
                        dns_test_common_lexicon.BaseLexiconAuthenticatorTest):

    def setUp(self):
        super(AuthenticatorTest, self).setUp()

        from certbot_dns_gandi.dns_gandi import Authenticator

        path = os.path.join(self.tempdir, 'file.ini')
        dns_test_common.write({"gandi_token": TOKEN}, path)

        self.config = mock.MagicMock(gandi_credentials=path,
                                     gandi_propagation_seconds=0)  # don't wait during tests

        self.auth = Authenticator(self.config, "gandi")

        self.mock_client = mock.MagicMock()
        # _get_gandi_client | pylint: disable=protected-access
        self.auth._get_gandi_client = mock.MagicMock(return_value=self.mock_client)


class GandiLexiconClientTest(unittest.TestCase, dns_test_common_lexicon.BaseLexiconClientTest):
    DOMAIN_NOT_FOUND = HTTPError('404 Client Error: Not Found for url: {0}.'.format(DOMAIN))
    LOGIN_ERROR = HTTPError('401 Client Error: Unauthorized for url: {0}.'.format(DOMAIN))

    def setUp(self):
        from certbot_dns_gandi.dns_gandi import _GandiLexiconClient

        self.client = _GandiLexiconClient(TOKEN, DOMAIN, 0)

        self.provider_mock = mock.MagicMock()
        self.client.provider = self.provider_mock


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
