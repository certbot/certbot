"""Tests for letsencrypt.client.plugins.nginx.parser."""
import os
import shutil
import sys
import unittest

import mock
import zope.component

from letsencrypt.client import errors
from letsencrypt.client.display import util as display_util

from letsencrypt.client.plugins.nginx.parser import NginxParser
from letsencrypt.client.plugins.nginx.tests import util


class NginxParserTest(util.NginxTest):
    """Nginx Parser Test."""

    def setUp(self):
        super(NginxParserTest, self).setUp()

        self.maxDiff = None
        zope.component.provideUtility(display_util.FileDisplay(sys.stdout))

    def tearDown(self):
        shutil.rmtree(self.temp_dir)
        shutil.rmtree(self.config_dir)
        shutil.rmtree(self.work_dir)

    def test_root_normalized(self):
        path = os.path.join(self.temp_dir, "debian_nginx_2_4/////"
                            "two_vhost_80/../../testdata")
        parser = NginxParser(path, None)
        self.assertEqual(parser.root, self.config_path)

    def test_root_absolute(self):
        parser = NginxParser(os.path.relpath(self.config_path), None)
        self.assertEqual(parser.root, self.config_path)

    def test_root_no_trailing_slash(self):
        parser = NginxParser(self.config_path + os.path.sep, None)
        self.assertEqual(parser.root, self.config_path)

    def test_parse(self):
        """Test recursive conf file parsing.

        """
        self.parser = NginxParser(self.config_path, self.ssl_options)
        self.assertEqual(set(map(self.parser.abs_path,
                             ['foo.conf', 'nginx.conf', 'server.conf',
                              'sites-enabled/default',
                              'sites-enabled/example.com'])),
                         set(self.parser.parsed.keys()))
        self.assertEqual([['server_name', 'somename  alias  another.alias']],
                         self.parser.parsed[self.parser.abs_path(
                             'server.conf')])
        self.assertEqual([[['server'], [['listen', '9000'],
                                        ['server_name', 'example.com']]]],
                         self.parser.parsed[self.parser.abs_path(
                             'sites-enabled/example.com')])

#    def test_find_dir(self):
#        from letsencrypt.client.plugins.nginx.parser import case_i
#        test = self.parser.find_dir(case_i("Listen"), "443")
#        # This will only look in enabled hosts
#        test2 = self.parser.find_dir(case_i("documentroot"))
#        self.assertEqual(len(test), 2)
#        self.assertEqual(len(test2), 3)
#
#    def test_add_dir(self):
#        aug_default = "/files" + self.parser.loc["default"]
#        self.parser.add_dir(aug_default, "AddDirective", "test")
#
#        self.assertTrue(
#            self.parser.find_dir("AddDirective", "test", aug_default))
#
#        self.parser.add_dir(aug_default, "AddList", ["1", "2", "3", "4"])
#        matches = self.parser.find_dir("AddList", None, aug_default)
#        for i, match in enumerate(matches):
#            self.assertEqual(self.parser.aug.get(match), str(i + 1))
#
#    def test_add_dir_to_ifmodssl(self):
#        """test add_dir_to_ifmodssl.
#
#        Path must be valid before attempting to add to augeas
#
#        """
#        from letsencrypt.client.plugins.nginx.parser import get_aug_path
#        self.parser.add_dir_to_ifmodssl(
#            get_aug_path(self.parser.loc["default"]),
#            "FakeDirective", "123")
#
#        matches = self.parser.find_dir("FakeDirective", "123")
#
#        self.assertEqual(len(matches), 1)
#        self.assertTrue("IfModule" in matches[0])
#
#    def test_get_aug_path(self):
#        from letsencrypt.client.plugins.nginx.parser import get_aug_path
#        self.assertEqual("/files/etc/nginx", get_aug_path("/etc/nginx"))
#
#    def test_set_locations(self):
#        with mock.patch("letsencrypt.client.plugins.nginx.parser."
#                        "os.path") as mock_path:
#
#            mock_path.isfile.return_value = False
#
#            # pylint: disable=protected-access
#            self.assertRaises(errors.LetsEncryptConfiguratorError,
#                              self.parser._set_locations, self.ssl_options)
#
#            mock_path.isfile.side_effect = [True, False, False]
#
#            # pylint: disable=protected-access
#            results = self.parser._set_locations(self.ssl_options)
#
#            self.assertEqual(results["default"], results["listen"])
#            self.assertEqual(results["default"], results["name"])


if __name__ == "__main__":
    unittest.main()
