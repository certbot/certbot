"""Tests for certbot_postfix.postconf."""

import subprocess
import unittest

import mock
import os
import random
import shutil
import string
import tempfile

rand_str = lambda n:''.join([random.choice(string.lowercase) for i in xrange(n)])

class PostConfTest(unittest.TestCase):
    """Tests for certbot_postfix.util.PostfixUtilBase."""

    def test_read_defalut(self):
        from certbot_postfix.postconf import ConfigMain
        config = ConfigMain('postconf')
        self.assertEqual(config.get_default('smtpd_sasl_auth_enable'), 'no')

    def test_read_write(self):
        from certbot_postfix.postconf import ConfigMain
        tmpdir = tempfile.mkdtemp(suffix=rand_str(10))
        try:
            shutil.copyfile('certbot-postfix/certbot_postfix/test_data/small.cf',
                            os.path.join(tmpdir, 'main.cf'))
            config = ConfigMain('postconf', tmpdir)
            config.set('inet_interfaces', '127.0.0.1')
            config.flush()
            with open(os.path.join(tmpdir, 'main.cf')) as f:
                self.assertTrue('inet_interfaces = 127.0.0.1\n' in f.readlines())
        finally:
            shutil.rmtree(tmpdir)

    def test_write_revert(self):
        from certbot_postfix.postconf import ConfigMain
        tmpdir = tempfile.mkdtemp(suffix=rand_str(10))
        try:
            shutil.copyfile('certbot-postfix/certbot_postfix/test_data/small.cf',
                            os.path.join(tmpdir, 'main.cf'))
            config = ConfigMain('postconf', tmpdir)
            config.set('postscreen_forbidden_commands', 'dummy_value')
            # revert config set
            config.set('postscreen_forbidden_commands', '$smtpd_forbidden_commands')
            config.flush()
            with open(os.path.join(tmpdir, 'main.cf')) as f:
                self.assertTrue(not any('postscreen_forbidden_commands' in line for line in f.readlines()))
        finally:
            shutil.rmtree(tmpdir)
    
    def test_write_default(self):
        from certbot_postfix.postconf import ConfigMain
        tmpdir = tempfile.mkdtemp(suffix=rand_str(10))
        try:
            shutil.copyfile('certbot-postfix/certbot_postfix/test_data/small.cf',
                            os.path.join(tmpdir, 'main.cf'))
            config = ConfigMain('postconf', tmpdir)
            config.set('postscreen_forbidden_commands', '$smtpd_forbidden_commands')
            config.flush()
            with open(os.path.join(tmpdir, 'main.cf')) as f:
                self.assertTrue(not any('postscreen_forbidden_commands' in line for line in f.readlines()))
        finally:
            shutil.rmtree(tmpdir)
    

if __name__ == '__main__':  # pragma: no cover
    unittest.main()
