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

from certbot_postfix import installer


# Fake Postfix Configs
names_only_config = """myhostname = mail.fubard.org
mydomain = fubard.org
myorigin = fubard.org"""


certs_only_config = (
"""smtpd_tls_cert_file = /etc/letsencrypt/live/www.fubard.org/fullchain.pem
smtpd_tls_key_file = /etc/letsencrypt/live/www.fubard.org/privkey.pem""")


class TestPostfixConfigGenerator(unittest.TestCase):

    def setUp(self):
        self.config = None
        self.postfix_dir = 'tests/'

    def testGetAllNames(self):
        sorted_names = ['fubard.org', 'mail.fubard.org']
        with mock.patch('certbot_postfix.installer.open') as mock_open:
            mock_open.return_value = six.StringIO(names_only_config)
            postfix_config_gen = installer.Installer(
                self.config,
                self.postfix_dir,
                fixup=True,
            )
        self.assertEqual(sorted_names, postfix_config_gen.get_all_names())

    def testGetAllCertAndKeys(self):
        return_vals = [('/etc/letsencrypt/live/www.fubard.org/fullchain.pem',
                        '/etc/letsencrypt/live/www.fubard.org/privkey.pem',
                        'tests/main.cf'),]
        with mock.patch('certbot_postfix.installer.open') as mock_open:
            mock_open.return_value = six.StringIO(certs_only_config)
            postfix_config_gen = installer.Installer(
                self.config,
                self.postfix_dir,
                fixup=True,
            )
        self.assertEqual(return_vals, postfix_config_gen.get_all_certs_keys())

    def testGetAllCertsAndKeys_With_None(self):
        with mock.patch('certbot_postfix.installer.open') as mock_open:
            mock_open.return_value = six.StringIO(names_only_config)
            postfix_config_gen = installer.Installer(
                self.config,
                self.postfix_dir,
                fixup=True,
            )
        self.assertEqual([], postfix_config_gen.get_all_certs_keys())


if __name__ == '__main__':
    unittest.main()
