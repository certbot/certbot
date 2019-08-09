"""Tests for certbot_dns_dreamhost.dns_dreamhost."""

import unittest

import mock

from certbot import errors
from certbot.compat import os
from certbot.plugins import dns_test_common
from certbot.plugins import dns_test_common_lexicon
from certbot.tests import util as test_util
from certbot_dns_dreamhost.dns_dreamhost import Authenticator

TOKEN = 'a-token'


class AuthenticatorTest(test_util.TempDirTestCase,
                        dns_test_common_lexicon.BaseLexiconAuthenticatorTest):

    def setUp(self):
        super(AuthenticatorTest, self).setUp()

        path = os.path.join(self.tempdir, 'file.ini')
        dns_test_common.write({"dreamhost_key": TOKEN}, path)

        self.config = mock.MagicMock(dreamhost_credentials=path,
                                     dreamhost_propagation_seconds=0)  # don't wait during tests

        self.auth = Authenticator(self.config, "dreamhost")

        self.mock_client = mock.MagicMock()
        # _get_dreamhost_client | pylint: disable=protected-access
        self.auth._get_dreamhost_client = mock.MagicMock(return_value=self.mock_client)

    # pylint: disable=protected-access
    def test_manual(self):
        path = os.path.join(self.tempdir, 'file_manual.ini')
        dns_test_common.write({"dreamhost_key": TOKEN}, path)

        config = mock.MagicMock(dreamhost_credentials=path,
                                dreamhost_propagation_seconds=0)
        auth = Authenticator(config, "dreamhost")
        auth._setup_credentials()
        client = auth._get_dreamhost_client()
        self.assertIsNotNone(client)


class DreamhostLexiconClientTest(unittest.TestCase, dns_test_common_lexicon.BaseLexiconClientTest):

    DOMAIN_NOT_FOUND = Exception('Domain not found')

    def setUp(self):
        from certbot_dns_dreamhost.dns_dreamhost import _DreamhostLexiconClient

        self.client = _DreamhostLexiconClient(TOKEN)

        self.provider_mock = mock.MagicMock()
        self.client.provider = self.provider_mock


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
