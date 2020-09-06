"""Tests for certbot_dns_dnsimple._internal.dns_dnsimple."""

import unittest

try:
    import mock
except ImportError: # pragma: no cover
    from unittest import mock # type: ignore
from requests.exceptions import HTTPError

from certbot.compat import os
from certbot.plugins import dns_test_common
from certbot.plugins import dns_test_common_lexicon
from certbot.tests import util as test_util

TOKEN = 'foo'


class AuthenticatorTest(test_util.TempDirTestCase,
                        dns_test_common_lexicon.BaseLexiconAuthenticatorTest):

    def setUp(self):
        super(AuthenticatorTest, self).setUp()

        from certbot_dns_dnsimple._internal.dns_dnsimple import Authenticator

        path = os.path.join(self.tempdir, 'file.ini')
        dns_test_common.write({"dnsimple_token": TOKEN}, path)

        self.configure(Authenticator(self.config, "dnsimple"), {"credentials": path})

        self.mock_client = mock.MagicMock()
        # _get_dnsimple_client | pylint: disable=protected-access
        self.auth._get_dnsimple_client = mock.MagicMock(return_value=self.mock_client)


class DNSimpleLexiconClientTest(unittest.TestCase, dns_test_common_lexicon.BaseLexiconClientTest):

    def login_error(self, domain):
        return HTTPError('401 Client Error: Unauthorized for url: {0}'.format(domain))

    def setUp(self):
        from certbot_dns_dnsimple._internal.dns_dnsimple import _DNSimpleLexiconClient

        self.client = _DNSimpleLexiconClient(TOKEN, 0)

        self.provider_mock = mock.MagicMock()
        self.client.provider = self.provider_mock


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
