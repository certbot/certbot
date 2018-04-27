"""Tests for certbot_postfix.postconf."""

import os
import pkg_resources
import random
import shutil
import string
import tempfile
import unittest

# TODO (sydneyli): Mock out calls to postconf
# TODO (sydneyli): inherit certbot.tests.util.TempDirTestCase

def _rand_str(n):
    """Returns a random string with length n, for use as a temporary directory."""
    return ''.join([random.choice(string.lowercase) for _ in xrange(n)])

class PostConfTest(unittest.TestCase):
    """Tests for certbot_postfix.util.PostfixUtilBase."""
    def setUp(self):
        from certbot_postfix.postconf import ConfigMain
        self.tmpdir = tempfile.mkdtemp(suffix=_rand_str(10))
        _config_file = pkg_resources.resource_filename("certbot_postfix.tests",
                           os.path.join("testdata", "small.cf"))
        self.config_path = os.path.join(self.tmpdir, 'main.cf')
        shutil.copyfile(_config_file, self.config_path)
        self.config = ConfigMain('postconf', self.tmpdir)

    def test_read_defalut(self):
        self.assertEqual(self.config.get_default('smtpd_sasl_auth_enable'), 'no')

    def test_read_write(self):
        try:
            self.config.set('inet_interfaces', '127.0.0.1')
            self.config.flush()
            with open(self.config_path) as f:
                self.assertTrue('inet_interfaces = 127.0.0.1\n' in f.readlines())
        finally:
            shutil.rmtree(self.tmpdir)

    def test_write_revert(self):
        try:
            self.config.set('postscreen_forbidden_commands', 'dummy_value')
            # revert config set
            self.config.set('postscreen_forbidden_commands', '$smtpd_forbidden_commands')
            self.config.flush()
            with open(self.config_path) as f:
                self.assertTrue(not any('postscreen_forbidden_commands' in line \
                                    for line in f.readlines()))
        finally:
            shutil.rmtree(self.tmpdir)

    def test_write_default(self):
        try:
            self.config.set('postscreen_forbidden_commands', '$smtpd_forbidden_commands')
            self.config.flush()
            with open(self.config_path) as f:
                self.assertTrue(not any('postscreen_forbidden_commands' in line \
                                    for line in f.readlines()))
        finally:
            shutil.rmtree(self.tmpdir)

if __name__ == '__main__':  # pragma: no cover
    unittest.main()
