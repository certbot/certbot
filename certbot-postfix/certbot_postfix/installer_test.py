#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import logging
import unittest

import mock
import six

# Fake Postfix Configs
names_only_config = """myhostname = mail.fubard.org
mydomain = fubard.org
myorigin = fubard.org"""


certs_only_config = (
"""smtpd_tls_cert_file = /etc/letsencrypt/live/www.fubard.org/fullchain.pem
smtpd_tls_key_file = /etc/letsencrypt/live/www.fubard.org/privkey.pem""")


class TestPostfixConfigGenerator(unittest.TestCase):

    def setUp(self):
        self.postfix_dir = 'tests/'

    def testGetAllNames(self):
        sorted_names = ['fubard.org', 'mail.fubard.org']
        with mock.patch('certbot_postfix.installer.open') as mock_open:
            mock_open.return_value = six.StringIO(names_only_config)
            postfix_config_gen = self._create_prepared_installer()
        self.assertEqual(sorted_names, postfix_config_gen.get_all_names())

    def testGetAllCertAndKeys(self):
        return_vals = [('/etc/letsencrypt/live/www.fubard.org/fullchain.pem',
                        '/etc/letsencrypt/live/www.fubard.org/privkey.pem',
                        'tests/main.cf'),]
        with mock.patch('certbot_postfix.installer.open') as mock_open:
            mock_open.return_value = six.StringIO(certs_only_config)
            postfix_config_gen = self._create_prepared_installer()
        self.assertEqual(return_vals, postfix_config_gen.get_all_certs_keys())

    def testGetAllCertsAndKeys_With_None(self):
        with mock.patch('certbot_postfix.installer.open') as mock_open:
            mock_open.return_value = six.StringIO(names_only_config)
            postfix_config_gen = self._create_prepared_installer()
        self.assertEqual([], postfix_config_gen.get_all_certs_keys())

    def _create_prepared_installer(self):
        """Creates and returns a new prepared Postfix Installer.

        Calls in prepare() are mocked out so the Postfix version check
        is successful.

        :returns: a prepared Postfix installer
        :rtype: certbot_postfix.installer.Installer

        """
        installer = self._create_installer()

        exe_exists_path = "certbot_postfix.installer.util.exe_exists"
        popen_path = "certbot_postfix.installer.subprocess.Popen"
        with mock.patch(exe_exists_path, return_value=True) as mock_exe_exists:
            with mock.patch(popen_path) as mock_popen:
                mock_popen().returncode = 0
                mock_popen().communicate.return_value = ("mail_version = 3.1.4", "")
                installer.prepare()

        return installer

    def _create_installer(self):
        """Creates and returns a new Postfix Installer.

        :returns: a new Postfix installer
        :rtype: certbot_postfix.installer.Installer

        """
        config = mock.MagicMock(postfix_config_dir=self.postfix_dir)
        name = "postfix"

        from certbot_postfix import installer
        return installer.Installer(config, name)


if __name__ == '__main__':
    unittest.main()
