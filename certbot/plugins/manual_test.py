"""Tests for certbot.plugins.manual"""
import unittest

import mock


class AuthenticatorTest(unittest.TestCase):
    """Tests for certbot.plugins.manual.Authenticator."""

    def setUp(self):
        self.config = mock.MagicMock(
            http01_port=0, manual_auth_hook=None, manual_cleanup_hook=None,
            manual_public_ip_logging_ok=False, noninteractive_mode=False)

        from certbot.plugins.manual import Authenticator
        self.auth = Authenticator(self.config, name='manual')
