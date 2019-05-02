"""Tests for certbot_dns_sakuracloud.dns_sakuracloud."""

import unittest

import mock
from requests.exceptions import HTTPError

from certbot.compat import os
from certbot.plugins import dns_test_common
from certbot.plugins import dns_test_common_lexicon
from certbot.tests import util as test_util

API_TOKEN = '00000000-0000-0000-0000-000000000000'
API_SECRET = 'MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAw'

class AuthenticatorTest(test_util.TempDirTestCase,
                        dns_test_common_lexicon.BaseLexiconAuthenticatorTest):

    def setUp(self):
        super(AuthenticatorTest, self).setUp()

        from certbot_dns_sakuracloud.dns_sakuracloud import Authenticator

        path = os.path.join(self.tempdir, 'file.ini')
        dns_test_common.write(
            {"sakuracloud_api_token": API_TOKEN, "sakuracloud_api_secret": API_SECRET},
            path
        )

        self.configure(Authenticator(self.config, "sakuracloud"), {"credentials": path})

        self.mock_client = mock.MagicMock()
        # _get_sakuracloud_client | pylint: disable=protected-access
        self.auth._get_sakuracloud_client = mock.MagicMock(return_value=self.mock_client)


class SakuraCloudLexiconClientTest(unittest.TestCase,
                                   dns_test_common_lexicon.BaseLexiconClientTest):

    def domain_not_found(self, domain):
        return HTTPError('404 Client Error: Not Found for url: {0}.'.format(domain))

    def login_error(self, domain):
        return HTTPError('401 Client Error: Unauthorized for url: {0}.'.format(domain))

    def setUp(self):
        from certbot_dns_sakuracloud.dns_sakuracloud import _SakuraCloudLexiconClient

        self.client = _SakuraCloudLexiconClient(API_TOKEN, API_SECRET, 0)

        self.provider_mock = mock.MagicMock()
        self.client.provider = self.provider_mock


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
