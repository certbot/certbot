"""Tests for letsencrypt_apache.parser."""
import os
import shutil
import sys
import unittest

import augeas
import mock
import zope.component

from letsencrypt import errors
from letsencrypt.display import util as display_util

from letsencrypt_apache.tests import util


class ApacheParserTest(util.ApacheTest):
    """Apache Parser Test."""

    def setUp(self):
        super(ApacheParserTest, self).setUp()

        zope.component.provideUtility(display_util.FileDisplay(sys.stdout))

        from letsencrypt_apache.parser import ApacheParser
        self.aug = augeas.Augeas(
            flags=augeas.Augeas.NONE | augeas.Augeas.NO_MODL_AUTOLOAD)
        with mock.patch("letsencrypt_apache.parser.ApacheParser."
                        "update_runtime_variables"):
            self.parser = ApacheParser(
                self.aug, self.config_path, self.ssl_options, "dummy_ctl_path")

    def tearDown(self):
        shutil.rmtree(self.temp_dir)
        shutil.rmtree(self.config_dir)
        shutil.rmtree(self.work_dir)

    def test_parse_file(self):
        """Test parse_file.

        letsencrypt.conf is chosen as the test file as it will not be
        included during the normal course of execution.

        """
        file_path = os.path.join(
            self.config_path, "sites-available", "letsencrypt.conf")

        self.parser._parse_file(file_path)  # pylint: disable=protected-access

        # search for the httpd incl
        matches = self.parser.aug.match(
            "/augeas/load/Httpd/incl [. ='%s']" % file_path)

        self.assertTrue(matches)

    def test_find_dir(self):
        from letsencrypt_apache.parser import case_i
        test = self.parser.find_dir(case_i("Listen"), "443")
        # This will only look in enabled hosts
        test2 = self.parser.find_dir(case_i("documentroot"))
        self.assertEqual(len(test), 2)
        self.assertEqual(len(test2), 3)

    def test_add_dir(self):
        aug_default = "/files" + self.parser.loc["default"]
        self.parser.add_dir(aug_default, "AddDirective", "test")

        self.assertTrue(
            self.parser.find_dir("AddDirective", "test", aug_default))

        self.parser.add_dir(aug_default, "AddList", ["1", "2", "3", "4"])
        matches = self.parser.find_dir("AddList", None, aug_default)
        for i, match in enumerate(matches):
            self.assertEqual(self.parser.aug.get(match), str(i + 1))

    def test_add_dir_to_ifmodssl(self):
        """test add_dir_to_ifmodssl.

        Path must be valid before attempting to add to augeas

        """
        from letsencrypt_apache.parser import get_aug_path
        self.parser.add_dir_to_ifmodssl(
            get_aug_path(self.parser.loc["default"]),
            "FakeDirective", "123")

        matches = self.parser.find_dir("FakeDirective", "123")

        self.assertEqual(len(matches), 1)
        self.assertTrue("IfModule" in matches[0])

    def test_get_aug_path(self):
        from letsencrypt_apache.parser import get_aug_path
        self.assertEqual("/files/etc/apache", get_aug_path("/etc/apache"))

    def test_set_locations(self):
        with mock.patch("letsencrypt_apache.parser.os.path") as mock_path:

            mock_path.isfile.return_value = False

            # pylint: disable=protected-access
            self.assertRaises(errors.PluginError,
                              self.parser._set_locations, self.ssl_options)

            mock_path.isfile.side_effect = [True, False, False]

            # pylint: disable=protected-access
            results = self.parser._set_locations(self.ssl_options)

            self.assertEqual(results["default"], results["listen"])
            self.assertEqual(results["default"], results["name"])


class ParserInitTest(util.ApacheTest):
    def setUp(self):
        super(ParserInitTest, self).setUp()
        self.aug = augeas.Augeas(
            flags=augeas.Augeas.NONE | augeas.Augeas.NO_MODL_AUTOLOAD)

    def tearDown(self):
        shutil.rmtree(self.temp_dir)
        shutil.rmtree(self.config_dir)
        shutil.rmtree(self.work_dir)

    def test_root_normalized(self):
        from letsencrypt_apache.parser import ApacheParser

        with mock.patch("letsencrypt_apache.parser.ApacheParser."
                        "update_runtime_variables"):
            path = os.path.join(
                self.temp_dir,
                "debian_apache_2_4/////two_vhost_80/../two_vhost_80/apache2")
            parser = ApacheParser(self.aug, path, None, "dummy_ctl")

        self.assertEqual(parser.root, self.config_path)

    def test_root_absolute(self):
        from letsencrypt_apache.parser import ApacheParser
        with mock.patch("letsencrypt_apache.parser.ApacheParser."
                        "update_runtime_variables"):
            parser = ApacheParser(
                self.aug, os.path.relpath(self.config_path), None, "dummy_ctl")

        self.assertEqual(parser.root, self.config_path)

    def test_root_no_trailing_slash(self):
        from letsencrypt_apache.parser import ApacheParser
        with mock.patch("letsencrypt_apache.parser.ApacheParser."
                        "update_runtime_variables"):
            parser = ApacheParser(
                self.aug, self.config_path + os.path.sep, None, "dummy_ctl")
        self.assertEqual(parser.root, self.config_path)

if __name__ == "__main__":
    unittest.main()  # pragma: no cover
