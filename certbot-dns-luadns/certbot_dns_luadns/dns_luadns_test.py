"""Tests for certbot_dns_luadns.dns_luadns."""

import os
import unittest

import mock
from requests.exceptions import HTTPError

from certbot.plugins import dns_test_common
from certbot.plugins import dns_test_common_lexicon
from certbot.tests import util as test_util

EMAIL = 'fake@example.com'
TOKEN = 'foo'


class AuthenticatorTest(test_util.TempDirTestCase,
                        dns_test_common_lexicon.BaseLexiconAuthenticatorTest):

    def setUp(self):
        super(AuthenticatorTest, self).setUp()

        from certbot_dns_luadns.dns_luadns import Authenticator

        path = os.path.join(self.tempdir, 'file.ini')
        dns_test_common.write({"luadns_email": EMAIL, "luadns_token": TOKEN}, path)

        self.config = mock.MagicMock(luadns_credentials=path,
                                     luadns_propagation_seconds=0)  # don't wait during tests

        self.auth = Authenticator(self.config, "luadns")

        self.mock_client = mock.MagicMock()
        # _get_luadns_client | pylint: disable=protected-access
        self.auth._get_luadns_client = mock.MagicMock(return_value=self.mock_client)


class LuaDNSLexiconClientTest(unittest.TestCase, dns_test_common_lexicon.BaseLexiconClientTest):

    LOGIN_ERROR = HTTPError("401 Client Error: Unauthorized for url: ...")

    def setUp(self):
        from certbot_dns_luadns.dns_luadns import _LuaDNSLexiconClient

        self.client = _LuaDNSLexiconClient(EMAIL, TOKEN, 0)

        self.provider_mock = mock.MagicMock()
        self.client.provider = self.provider_mock


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
