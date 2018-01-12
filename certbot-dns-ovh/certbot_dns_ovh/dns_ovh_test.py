"""Tests for certbot_dns_ovh.dns_ovh."""

import os
import unittest

import mock
from requests.exceptions import HTTPError

from certbot.plugins import dns_test_common
from certbot.plugins import dns_test_common_lexicon
from certbot.tests import util as test_util

ENDPOINT = 'ovh-eu'
APPLICATION_KEY = 'foo'
APPLICATION_SECRET = 'bar'
CONSUMER_KEY = 'spam'


class AuthenticatorTest(test_util.TempDirTestCase,
                        dns_test_common_lexicon.BaseLexiconAuthenticatorTest):

    def setUp(self):
        super(AuthenticatorTest, self).setUp()

        from certbot_dns_ovh.dns_ovh import Authenticator

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

        self.auth = Authenticator(self.config, "ovh")

        self.mock_client = mock.MagicMock()
        # _get_ovh_client | pylint: disable=protected-access
        self.auth._get_ovh_client = mock.MagicMock(return_value=self.mock_client)


class OVHLexiconClientTest(unittest.TestCase, dns_test_common_lexicon.BaseLexiconClientTest):

    LOGIN_ERROR = HTTPError('401 Client Error: Unauthorized for url: ...')

    def setUp(self):
        from certbot_dns_ovh.dns_ovh import _OVHLexiconClient

        self.client = _OVHLexiconClient(
            ENDPOINT, APPLICATION_KEY, APPLICATION_SECRET, CONSUMER_KEY, 0
        )

        self.provider_mock = mock.MagicMock()
        self.client.provider = self.provider_mock


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
