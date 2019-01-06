"""Tests for certbot_dns_standalone.dns_standalone."""

import os
import unittest

import mock

from certbot import errors
from certbot.plugins import dns_test_common
from certbot.plugins.dns_test_common import DOMAIN
from certbot.tests import util as test_util


class AuthenticatorTest(test_util.TempDirTestCase, dns_test_common.BaseAuthenticatorTest):

    def setUp(self):
        from certbot_dns_standalone.dns_standalone import Authenticator

        super(AuthenticatorTest, self).setUp()

        self.config = mock.MagicMock(standalone_address='127.0.0.1')

        self.auth = Authenticator(self.config, "standalone")

    def test_perform(self):
        return # TODO

    def test_perform(self):
        return # TODO


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
