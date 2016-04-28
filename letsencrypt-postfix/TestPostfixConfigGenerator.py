#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import io
import logging
import unittest

import Config
import PostfixConfigGenerator as pcg


logger = logging.getLogger(__name__)
logger.addHandler(logging.StreamHandler())


# Fake Postfix Configs
names_only_config = """myhostname = mail.fubard.org
mydomain = fubard.org
myorigin = fubard.org"""


certs_only_config = (
"""smtpd_tls_cert_file = /etc/letsencrypt/live/www.fubard.org/fullchain.pem
smtpd_tls_key_file = /etc/letsencrypt/live/www.fubard.org/privkey.pem""")


def GetFakeOpen(fake_file_contents):
    fake_file = io.StringIO()
    # cast this to unicode for py2
    fake_file.write(fake_file_contents)
    fake_file.seek(0)

    def FakeOpen(_):
        return fake_file

    return FakeOpen

  
class TestPostfixConfigGenerator(unittest.TestCase):

    def setUp(self):
        self.fopen_names_only_config = GetFakeOpen(names_only_config)        
        self.fopen_certs_only_config = GetFakeOpen(certs_only_config)
        self.fopen_no_certs_only_config = self.fopen_names_only_config

        #self.config = Config.Config()
        self.config = None
        self.postfix_dir = 'tests/'

    def tearDown(self):
        pass

    def testGetAllNames(self):
        sorted_names = ['fubard.org', 'mail.fubard.org']
        postfix_config_gen = pcg.PostfixConfigGenerator(
            self.config,
            self.postfix_dir,
            fixup=True,
            fopen=self.fopen_names_only_config
        )
        self.assertEqual(sorted_names, postfix_config_gen.get_all_names())

    def testGetAllCertAndKeys(self):
        return_vals = [('/etc/letsencrypt/live/www.fubard.org/fullchain.pem',
                        '/etc/letsencrypt/live/www.fubard.org/privkey.pem',
                        'tests/main.cf'),]
        postfix_config_gen = pcg.PostfixConfigGenerator(
            self.config,
            self.postfix_dir,
            fixup=True,
            fopen=self.fopen_certs_only_config
        )
        self.assertEqual(return_vals, postfix_config_gen.get_all_certs_keys())

    def testGetAllCertsAndKeys_With_None(self):
        postfix_config_gen = pcg.PostfixConfigGenerator(
            self.config,
            self.postfix_dir,
            fixup=True,
            fopen=self.fopen_no_certs_only_config
        )
        self.assertEqual([], postfix_config_gen.get_all_certs_keys())


if __name__ == '__main__':
    unittest.main()
