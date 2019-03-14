"""Tests for certbot.plugins.manual"""
import os
import unittest

import six
import mock
import sys

from acme import challenges

from certbot import errors

from certbot.tests import acme_util
from certbot.tests import util as test_util


class AuthenticatorTest(test_util.TempDirTestCase):
    """Tests for certbot.plugins.manual.Authenticator."""

    def setUp(self):
        super(AuthenticatorTest, self).setUp()
        self.http_achall = acme_util.HTTP01_A
        self.dns_achall = acme_util.DNS01_A
        self.dns_achall_2 = acme_util.DNS01_A_2
        self.achalls = [self.http_achall, self.dns_achall, self.dns_achall_2]
        for d in ["config_dir", "work_dir", "in_progress"]:
            os.mkdir(os.path.join(self.tempdir, d))
            # "backup_dir" and "temp_checkpoint_dir" get created in
            # certbot.util.make_or_verify_dir() during the Reverter
            # initialization.
        self.config = mock.MagicMock(
            http01_port=0, manual_auth_hook=None, manual_cleanup_hook=None,
            manual_public_ip_logging_ok=False, noninteractive_mode=False,
            validate_hooks=False,
            config_dir=os.path.join(self.tempdir, "config_dir"),
            work_dir=os.path.join(self.tempdir, "work_dir"),
            backup_dir=os.path.join(self.tempdir, "backup_dir"),
            temp_checkpoint_dir=os.path.join(
                                        self.tempdir, "temp_checkpoint_dir"),
            in_progress_dir=os.path.join(self.tempdir, "in_progess"))

        from certbot.plugins.manual import Authenticator
        self.auth = Authenticator(self.config, name='manual')

    def test_prepare_no_hook_noninteractive(self):
        self.config.noninteractive_mode = True
        self.assertRaises(errors.PluginError, self.auth.prepare)

    def test_prepare_bad_hook(self):
        self.config.manual_auth_hook = os.path.abspath(os.sep)  # is / on UNIX
        self.config.validate_hooks = True
        self.assertRaises(errors.HookCommandNotFound, self.auth.prepare)

    def test_more_info(self):
        self.assertTrue(isinstance(self.auth.more_info(), six.string_types))

    def test_get_chall_pref(self):
        self.assertEqual(self.auth.get_chall_pref('example.org'),
                         [challenges.HTTP01, challenges.DNS01])

    @test_util.patch_get_utility()
    def test_ip_logging_not_ok(self, mock_get_utility):
        mock_get_utility().yesno.return_value = False
        self.assertRaises(errors.PluginError, self.auth.perform, [])

    @test_util.patch_get_utility()
    def test_ip_logging_ok(self, mock_get_utility):
        mock_get_utility().yesno.return_value = True
        self.auth.perform([])
        self.assertTrue(self.config.manual_public_ip_logging_ok)

    def test_script_perform(self):
        self.config.manual_public_ip_logging_ok = True
        self.config.manual_auth_hook = (
            '{0} -c "from __future__ import print_function;'
            'import os;  print(os.environ.get(\'CERTBOT_DOMAIN\'));'
            'print(os.environ.get(\'CERTBOT_TOKEN\', \'notoken\'));'
            'print(os.environ.get(\'CERTBOT_VALIDATION\', \'novalidation\'));"'
            .format(sys.executable))
        dns_expected = '{0}\n{1}\n{2}'.format(
            self.dns_achall.domain, 'notoken',
            self.dns_achall.validation(self.dns_achall.account_key))
        http_expected = '{0}\n{1}\n{2}'.format(
            self.http_achall.domain, self.http_achall.chall.encode('token'),
            self.http_achall.validation(self.http_achall.account_key))

        self.assertEqual(
            self.auth.perform(self.achalls),
            [achall.response(achall.account_key) for achall in self.achalls])
        self.assertEqual(
            self.auth.env[self.dns_achall]['CERTBOT_AUTH_OUTPUT'],
            dns_expected)
        self.assertEqual(
            self.auth.env[self.http_achall]['CERTBOT_AUTH_OUTPUT'],
            http_expected)

    @test_util.patch_get_utility()
    def test_manual_perform(self, mock_get_utility):
        self.config.manual_public_ip_logging_ok = True
        self.assertEqual(
            self.auth.perform(self.achalls),
            [achall.response(achall.account_key) for achall in self.achalls])
        for i, (args, kwargs) in enumerate(mock_get_utility().notification.call_args_list):
            achall = self.achalls[i]
            self.assertTrue(
                achall.validation(achall.account_key) in args[0])
            self.assertFalse(kwargs['wrap'])

    @test_util.broken_on_windows
    def test_cleanup(self):
        self.config.manual_public_ip_logging_ok = True
        self.config.manual_auth_hook = 'echo foo;'
        self.config.manual_cleanup_hook = '# cleanup'
        self.auth.perform(self.achalls)

        for achall in self.achalls:
            self.auth.cleanup([achall])
            self.assertEqual(os.environ['CERTBOT_AUTH_OUTPUT'], 'foo')
            self.assertEqual(os.environ['CERTBOT_DOMAIN'], achall.domain)
            if (isinstance(achall.chall, challenges.HTTP01) or
                isinstance(achall.chall, challenges.DNS01)):
                self.assertEqual(
                    os.environ['CERTBOT_VALIDATION'],
                    achall.validation(achall.account_key))
            if isinstance(achall.chall, challenges.HTTP01):
                self.assertEqual(
                    os.environ['CERTBOT_TOKEN'],
                    achall.chall.encode('token'))
            else:
                self.assertFalse('CERTBOT_TOKEN' in os.environ)


if __name__ == '__main__':
    unittest.main()  # pragma: no cover
