"""Tests for certbot_dns_online.dns_online."""

import os
import unittest

import mock

from certbot.plugins import dns_test_common
from certbot.plugins import dns_test_common_lexicon
from certbot.tests import util as test_util

APPLICATION_TOKEN = 'xxxxwxxx'


class AuthenticatorTest(test_util.TempDirTestCase,
                        dns_test_common_lexicon.BaseLexiconAuthenticatorTest):

    def setUp(self):
        super(AuthenticatorTest, self).setUp()

        from certbot_dns_online.dns_online import Authenticator

        path = os.path.join(self.tempdir, 'file.ini')
        credentials = {
            "online_application_token": APPLICATION_TOKEN,
        }
        dns_test_common.write(credentials, path)

        self.config = mock.MagicMock(online_credentials=path,
                                     online_propagation_seconds=0)  # don't wait during tests

        self.auth = Authenticator(self.config, "online")

        self.mock_client = mock.MagicMock()
        # _get_online_client | pylint: disable=protected-access
        self.auth._get_online_client = mock.MagicMock(return_value=self.mock_client)


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
