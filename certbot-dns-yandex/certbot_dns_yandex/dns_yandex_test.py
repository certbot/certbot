"""Tests for certbot_dns_yandex.dns_yandex."""

import os
import unittest

import mock

from certbot.plugins import dns_test_common
from certbot.plugins import dns_test_common_lexicon
from certbot.tests import util as test_util

TOKEN = 'foo'


class AuthenticatorTest(test_util.TempDirTestCase,
                        dns_test_common_lexicon.BaseLexiconAuthenticatorTest):

    def setUp(self):
        super(AuthenticatorTest, self).setUp()

        from certbot_dns_yandex.dns_yandex import Authenticator

        path = os.path.join(self.tempdir, 'file.ini')
        dns_test_common.write({"yandex_token": TOKEN}, path)

        self.config = mock.MagicMock(yandex_credentials=path,
                                     yandex_propagation_seconds=0)  # don't wait during tests

        self.auth = Authenticator(self.config, "yandex")

        self.mock_client = mock.MagicMock()
        # _get_yandex_client | pylint: disable=protected-access
        self.auth._get_yandex_client = mock.MagicMock(return_value=self.mock_client)


class YandexLexiconClientTest(unittest.TestCase, dns_test_common_lexicon.BaseLexiconClientTest):

    DOMAIN_NOT_FOUND = Exception('')

    def setUp(self):
        from certbot_dns_yandex.dns_yandex import _YandexLexiconClient

        self.client = _YandexLexiconClient(TOKEN, 0)

        self.provider_mock = mock.MagicMock()
        self.client.provider = self.provider_mock

if __name__ == "__main__":
    unittest.main()  # pragma: no cover
