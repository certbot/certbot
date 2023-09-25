"""Tests for certbot_dns_luadns._internal.dns_luadns."""
import sys
from unittest import mock

import pytest
from requests.exceptions import HTTPError

from certbot.compat import os
from certbot.plugins import dns_test_common
from certbot.plugins import dns_test_common_lexicon
from certbot.tests import util as test_util

EMAIL = 'fake@example.com'
TOKEN = 'foo'


class AuthenticatorTest(test_util.TempDirTestCase,
                        dns_test_common_lexicon.BaseLexiconDNSAuthenticatorTest):

    LOGIN_ERROR = HTTPError("401 Client Error: Unauthorized for url: ...")

    def setUp(self):
        super().setUp()

        from certbot_dns_luadns._internal.dns_luadns import Authenticator

        path = os.path.join(self.tempdir, 'file.ini')
        dns_test_common.write({"luadns_email": EMAIL, "luadns_token": TOKEN}, path)

        self.config = mock.MagicMock(luadns_credentials=path,
                                     luadns_propagation_seconds=0)  # don't wait during tests

        self.auth = Authenticator(self.config, "luadns")


if __name__ == "__main__":
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover
