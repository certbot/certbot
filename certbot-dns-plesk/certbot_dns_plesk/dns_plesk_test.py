"""Tests for certbot_dns_plesk.dns_plesk."""

import os
import unittest

import mock
from requests.exceptions import HTTPError

from certbot.plugins import dns_test_common
from certbot.plugins import dns_test_common_lexicon
from certbot.tests import util as test_util

TOKEN = 'foo'


class AuthenticatorTest(test_util.TempDirTestCase,
                        dns_test_common_lexicon.BaseLexiconAuthenticatorTest):

    def setUp(self):
        super(AuthenticatorTest, self).setUp()

        from certbot_dns_plesk.dns_plesk import Authenticator

        path = os.path.join(self.tempdir, 'file.ini')
        dns_test_common.write({"plesk_token": TOKEN}, path)

        self.config = mock.MagicMock(plesk_credentials=path,
                                     plesk_propagation_seconds=0)  # don't wait during tests

        self.auth = Authenticator(self.config, "plesk")

        self.mock_client = mock.MagicMock()
        # _get_plesk_client | pylint: disable=protected-access
        self.auth._get_plesk_client = mock.MagicMock(return_value=self.mock_client)


class PleskLexiconClientTest(unittest.TestCase, dns_test_common_lexicon.BaseLexiconClientTest):

    LOGIN_ERROR = HTTPError('401 Client Error: Unauthorized for url: ...')

    def setUp(self):
        from certbot_dns_plesk.dns_plesk import _PleskLexiconClient

        self.client = _PleskLexiconClient(TOKEN, 0)

        self.provider_mock = mock.MagicMock()
        self.client.provider = self.provider_mock


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
