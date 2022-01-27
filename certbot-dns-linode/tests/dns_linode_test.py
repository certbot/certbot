"""Tests for certbot_dns_linode._internal.dns_linode."""

import unittest

try:
    import mock
except ImportError: # pragma: no cover
    from unittest import mock # type: ignore

from certbot import errors
from certbot.compat import os
from certbot.plugins import dns_test_common
from certbot.plugins import dns_test_common_lexicon
from certbot.tests import util as test_util
from certbot_dns_linode._internal.dns_linode import Authenticator

TOKEN = 'a-token'
TOKEN_V3 = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ64'
TOKEN_V4 = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'


class AuthenticatorTest(test_util.TempDirTestCase,
                        dns_test_common_lexicon.BaseLexiconAuthenticatorTest):

    def setUp(self):
        super().setUp()

        path = os.path.join(self.tempdir, 'file.ini')
        dns_test_common.write({"linode_key": TOKEN}, path)

        self.config = mock.MagicMock(linode_credentials=path,
                                     linode_propagation_seconds=0)  # don't wait during tests

        self.auth = Authenticator(self.config, "linode")

        self.mock_client = mock.MagicMock()
        # _get_linode_client | pylint: disable=protected-access
        self.auth._get_linode_client = mock.MagicMock(return_value=self.mock_client)

    # pylint: disable=protected-access
    def test_api_version_3_detection(self):
        path = os.path.join(self.tempdir, 'file_3_auto.ini')
        dns_test_common.write({"linode_key": TOKEN_V3}, path)

        config = mock.MagicMock(linode_credentials=path,
                                linode_propagation_seconds=0)
        auth = Authenticator(config, "linode")
        auth._setup_credentials()
        client = auth._get_linode_client()
        self.assertEqual(3, client.api_version)

    # pylint: disable=protected-access
    def test_api_version_4_detection(self):
        path = os.path.join(self.tempdir, 'file_4_auto.ini')
        dns_test_common.write({"linode_key": TOKEN_V4}, path)

        config = mock.MagicMock(linode_credentials=path,
                                linode_propagation_seconds=0)
        auth = Authenticator(config, "linode")
        auth._setup_credentials()
        client = auth._get_linode_client()
        self.assertEqual(4, client.api_version)

    # pylint: disable=protected-access
    def test_api_version_3_detection_empty_version(self):
        path = os.path.join(self.tempdir, 'file_3_auto_empty.ini')
        dns_test_common.write({"linode_key": TOKEN_V3, "linode_version": ""}, path)

        config = mock.MagicMock(linode_credentials=path,
                                linode_propagation_seconds=0)
        auth = Authenticator(config, "linode")
        auth._setup_credentials()
        client = auth._get_linode_client()
        self.assertEqual(3, client.api_version)

    # pylint: disable=protected-access
    def test_api_version_4_detection_empty_version(self):
        path = os.path.join(self.tempdir, 'file_4_auto_empty.ini')
        dns_test_common.write({"linode_key": TOKEN_V4, "linode_version": ""}, path)

        config = mock.MagicMock(linode_credentials=path,
                                linode_propagation_seconds=0)
        auth = Authenticator(config, "linode")
        auth._setup_credentials()
        client = auth._get_linode_client()
        self.assertEqual(4, client.api_version)

    # pylint: disable=protected-access
    def test_api_version_3_manual(self):
        path = os.path.join(self.tempdir, 'file_3_manual.ini')
        dns_test_common.write({"linode_key": TOKEN_V4, "linode_version": 3}, path)

        config = mock.MagicMock(linode_credentials=path,
                                linode_propagation_seconds=0)
        auth = Authenticator(config, "linode")
        auth._setup_credentials()
        client = auth._get_linode_client()
        self.assertEqual(3, client.api_version)

    # pylint: disable=protected-access
    def test_api_version_4_manual(self):
        path = os.path.join(self.tempdir, 'file_4_manual.ini')
        dns_test_common.write({"linode_key": TOKEN_V3, "linode_version": 4}, path)

        config = mock.MagicMock(linode_credentials=path,
                                linode_propagation_seconds=0)
        auth = Authenticator(config, "linode")
        auth._setup_credentials()
        client = auth._get_linode_client()
        self.assertEqual(4, client.api_version)

    # pylint: disable=protected-access
    def test_api_version_error(self):
        path = os.path.join(self.tempdir, 'file_version_error.ini')
        dns_test_common.write({"linode_key": TOKEN_V3, "linode_version": 5}, path)

        config = mock.MagicMock(linode_credentials=path,
                                linode_propagation_seconds=0)
        auth = Authenticator(config, "linode")
        auth._setup_credentials()
        self.assertRaises(errors.PluginError, auth._get_linode_client)


class LinodeLexiconClientTest(unittest.TestCase, dns_test_common_lexicon.BaseLexiconClientTest):

    DOMAIN_NOT_FOUND = Exception('Domain not found')

    def setUp(self):
        from certbot_dns_linode._internal.dns_linode import _LinodeLexiconClient

        self.client = _LinodeLexiconClient(TOKEN, 3)

        self.provider_mock = mock.MagicMock()
        self.client.provider = self.provider_mock


class Linode4LexiconClientTest(unittest.TestCase, dns_test_common_lexicon.BaseLexiconClientTest):

    DOMAIN_NOT_FOUND = Exception('Domain not found')

    def setUp(self):
        from certbot_dns_linode._internal.dns_linode import _LinodeLexiconClient

        self.client = _LinodeLexiconClient(TOKEN, 4)

        self.provider_mock = mock.MagicMock()
        self.client.provider = self.provider_mock


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
