#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import functools
import logging
import os
import subprocess
import unittest

import mock
import six

from certbot import errors
from certbot.tests import util as certbot_test_util

# Fake Postfix Configs
names_only_config = """mydomain = fubard.org
myhostname = mail.fubard.org
myorigin = fubard.org"""


class InstallerTest(certbot_test_util.TempDirTestCase):

    def setUp(self):
        super(InstallerTest, self).setUp()
        self.config = mock.MagicMock(postfix_config_dir=self.tempdir,
                                     postfix_config_utility="postconf")

    def test_add_parser_arguments(self):
        mock_add = mock.MagicMock()

        from certbot_postfix import installer
        installer.Installer.add_parser_arguments(mock_add)

        for call in mock_add.call_args_list:
            self.assertTrue(call[0][0] in ('config-dir', 'config-utility'))

    def test_no_postconf_prepare(self):
        installer = self._create_installer()

        installer_path = "certbot_postfix.installer"
        exe_exists_path = installer_path + ".certbot_util.exe_exists"
        path_surgery_path = installer_path + ".plugins_util.path_surgery"

        with mock.patch(path_surgery_path, return_value=False):
            with mock.patch(exe_exists_path, return_value=False):
                self.assertRaises(errors.NoInstallationError, installer.prepare)

    def test_set_config_dir(self):
        self.config.postfix_config_dir = os.path.join(self.tempdir, "subdir")
        os.mkdir(self.config.postfix_config_dir)
        installer = self._create_installer()

        expected = self.config.postfix_config_dir
        self.config.postfix_config_dir = None

        check_output_path = "certbot_postfix.installer.util.check_output"
        exe_exists_path = "certbot_postfix.installer.certbot_util.exe_exists"
        with mock.patch(check_output_path) as mock_check_output:
            mock_check_output.side_effect = [
                "config_directory = " + expected, "mail_version = 3.1.4"
            ]
            with mock.patch(exe_exists_path, return_value=True):
                installer.prepare()
        self.assertEqual(installer.config_dir, expected)

    def test_lock_error(self):
        assert_raises = functools.partial(self.assertRaises,
                                          errors.PluginError,
                                          self._create_prepared_installer)
        certbot_test_util.lock_and_call(assert_raises, self.tempdir)

    @mock.patch("certbot_postfix.installer.util.check_output")
    def test_get_all_names(self, mock_check_output):
        installer = self._create_prepared_installer()
        mock_check_output.side_effect = names_only_config.splitlines()

        result = installer.get_all_names()
        self.assertTrue("fubard.org" in result)
        self.assertTrue("mail.fubard.org" in result)

    def test_enhance(self):
        self.assertRaises(errors.PluginError,
                          self._create_prepared_installer().enhance,
                          "example.org", "redirect")

    def test_supported_enhancements(self):
        self.assertEqual(
            self._create_prepared_installer().supported_enhancements(), [])

    def test_get_config_var_success(self):
        self.config.postfix_config_dir = None

        command = self._test_get_config_var_success_common('foo', False)
        self.assertFalse("-c" in command)
        self.assertFalse("-d" in command)

    def test_get_config_var_success_with_config(self):
        command = self._test_get_config_var_success_common('foo', False)
        self.assertTrue("-c" in command)
        self.assertFalse("-d" in command)

    def test_get_config_var_success_with_default(self):
        self.config.postfix_config_dir = None

        command = self._test_get_config_var_success_common('foo', True)
        self.assertFalse("-c" in command)
        self.assertTrue("-d" in command)

    @mock.patch("certbot_postfix.installer.logger")
    @mock.patch("certbot_postfix.installer.util.check_output")
    def test_get_config_var_failure(self, mock_check_output, mock_logger):
        mock_check_output.side_effect = subprocess.CalledProcessError(42, "foo")
        installer = self._create_installer()
        self.assertRaises(errors.PluginError, installer.get_config_var, "foo")
        self.assertTrue(mock_logger.debug.call_args[1]["exc_info"])

    @mock.patch("certbot_postfix.installer.util.check_output")
    def test_get_config_var_unexpected_output(self, mock_check_output):
        self.config.postfix_config_dir = None
        mock_check_output.return_value = "foo"

        installer = self._create_installer()
        self.assertRaises(errors.PluginError, installer.get_config_var, "foo")

    def _test_get_config_var_success_common(self, name, default):
        installer = self._create_installer()

        check_output_path = "certbot_postfix.installer.util.check_output"
        with mock.patch(check_output_path) as mock_check_output:
            value = "bar"
            mock_check_output.return_value = name + " = " + value
            self.assertEqual(installer.get_config_var(name, default), value)

        return mock_check_output.call_args[0][0]

    def _create_prepared_installer(self):
        """Creates and returns a new prepared Postfix Installer.

        Calls in prepare() are mocked out so the Postfix version check
        is successful.

        :returns: a prepared Postfix installer
        :rtype: certbot_postfix.installer.Installer

        """
        installer = self._create_installer()

        check_output_path = "certbot_postfix.installer.util.check_output"
        exe_exists_path = "certbot_postfix.installer.certbot_util.exe_exists"
        with mock.patch(check_output_path) as mock_check_output:
            with mock.patch(exe_exists_path, return_value=True):
                mock_check_output.return_value = "mail_version = 3.1.4"
                installer.prepare()

        return installer

    def _create_installer(self):
        """Creates and returns a new Postfix Installer.

        :returns: a new Postfix installer
        :rtype: certbot_postfix.installer.Installer

        """
        name = "postfix"

        from certbot_postfix import installer
        return installer.Installer(self.config, name)


if __name__ == '__main__':
    unittest.main()
