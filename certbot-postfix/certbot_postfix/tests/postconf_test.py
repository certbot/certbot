"""Tests for certbot_postfix.postconf."""

import os
import pkg_resources
import shutil
import unittest

from certbot.tests import util as test_util

# TODO (sydneyli): Mock out calls to postconf

class PostConfTest(test_util.TempDirTestCase):
    """Tests for certbot_postfix.util.PostfixUtilBase."""
    def setUp(self):
        from certbot_postfix.postconf import ConfigMain
        super(PostConfTest, self).setUp()
        _config_file = pkg_resources.resource_filename("certbot_postfix.tests",
                           os.path.join("testdata", "small.cf"))
        self.config_path = os.path.join(self.tempdir, 'main.cf')
        shutil.copyfile(_config_file, self.config_path)
        self.config = ConfigMain('postconf', self.tempdir)

    def test_read_defalut(self):
        self.assertEqual(self.config.get_default('smtpd_sasl_auth_enable'), 'no')

    def test_read_write(self):
        self.config.set('inet_interfaces', '127.0.0.1')
        self.config.flush()
        with open(self.config_path) as f:
            self.assertTrue('inet_interfaces = 127.0.0.1\n' in f.readlines())

    def test_write_revert(self):
        self.config.set('postscreen_forbidden_commands', 'dummy_value')
        # revert config set
        self.config.set('postscreen_forbidden_commands', '$smtpd_forbidden_commands')
        self.config.flush()
        with open(self.config_path) as f:
            self.assertTrue(not any('postscreen_forbidden_commands' in line \
                                for line in f.readlines()))

    def test_write_default(self):
        self.config.set('postscreen_forbidden_commands', '$smtpd_forbidden_commands')
        self.config.flush()
        with open(self.config_path) as f:
            self.assertTrue(not any('postscreen_forbidden_commands' in line \
                                for line in f.readlines()))

if __name__ == '__main__':  # pragma: no cover
    unittest.main()
