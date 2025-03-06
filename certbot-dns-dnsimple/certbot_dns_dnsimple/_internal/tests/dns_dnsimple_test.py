"""Tests for certbot_dns_dnsimple._internal.dns_dnsimple."""
import sys
from unittest import mock

import pytest
from requests import Response
from requests.exceptions import HTTPError

from certbot.compat import os
from certbot.plugins import dns_test_common
from certbot.plugins import dns_test_common_lexicon
from certbot.tests import util as test_util

TOKEN = 'foo'


class AuthenticatorTest(test_util.TempDirTestCase,
                        dns_test_common_lexicon.BaseLexiconDNSAuthenticatorTest):

    LOGIN_ERROR = HTTPError('401 Client Error: Unauthorized for url: ...', response=Response())

    def setUp(self):
        super().setUp()

        from certbot_dns_dnsimple._internal.dns_dnsimple import Authenticator

        path = os.path.join(self.tempdir, 'file.ini')
        dns_test_common.write({"dnsimple_token": TOKEN}, path)

        self.config = mock.MagicMock(dnsimple_credentials=path,
                                     dnsimple_propagation_seconds=0)  # don't wait during tests

        self.auth = Authenticator(self.config, "dnsimple")


if __name__ == "__main__":
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover
