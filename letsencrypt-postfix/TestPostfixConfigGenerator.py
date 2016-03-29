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
        #self.config = Config.Config()
        self.config = None
        self.postfix_dir = 'tests/'

    def tearDown(self):
        pass

    def testGetAllNames(self):
        sorted_names = ('fubard.org', 'mail.fubard.org')
        postfix_config_gen = pcg.PostfixConfigGenerator(
            self.config,
            self.postfix_dir,
            fixup=True,
            fopen=self.fopen_names_only_config
        )
        self.assertEqual(sorted_names, postfix_config_gen.get_all_names())


if __name__ == '__main__':
    unittest.main()
