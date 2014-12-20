import os
import shutil
import sys
import unittest

import augeas
import mock

from letsencrypt.client import display
from letsencrypt.client import errors
from letsencrypt.client.apache import parser
from letsencrypt.client.tests import config_util


class ApacheParserTest(unittest.TestCase):

    def setUp(self):
        display.set_display(display.FileDisplay(sys.stdout))

        self.temp_dir, self.config_dir, self.work_dir = config_util.dir_setup(
            "debian_apache_2_4/two_vhost_80")

        self.ssl_options = config_util.setup_apache_ssl_options(self.config_dir)

        # Final slash is currently important
        self.config_path = os.path.join(
            self.temp_dir, "debian_apache_2_4/two_vhost_80/apache2/")

        self.parser = parser.ApacheParser(
            augeas.Augeas(flags=augeas.Augeas.NONE),
            self.config_path, self.ssl_options)

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

        # pylint: disable=protected-access
        self.parser._parse_file(file_path)

        # search for the httpd incl
        matches = self.parser.aug.match(
            "/augeas/load/Httpd/incl [. ='%s']" % file_path)

        self.assertTrue(matches)

    def test_find_dir(self):
        test = self.parser.find_dir(parser.case_i("Listen"), "443")
        # This will only look in enabled hosts
        test2 = self.parser.find_dir(
            parser.case_i("documentroot"))
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
        self.parser.add_dir_to_ifmodssl(
            parser.get_aug_path(self.parser.loc["default"]),
            "FakeDirective", "123")

        matches = self.parser.find_dir("FakeDirective", "123")

        self.assertEqual(len(matches), 1)
        self.assertTrue("IfModule" in matches[0])

    def test_get_aug_path(self):
        self.assertEqual(
            "/files/etc/apache", parser.get_aug_path("/etc/apache"))

    def test_set_locations(self):
        with mock.patch("letsencrypt.client.apache.parser."
                        "os.path") as mock_path:

            mock_path.isfile.return_value = False

            # pylint: disable=protected-access
            self.assertRaises(errors.LetsEncryptConfiguratorError,
                              self.parser._set_locations, self.ssl_options)

            mock_path.isfile.side_effect = [True, False, False]

            # pylint: disable=protected-access
            results = self.parser._set_locations(self.ssl_options)

            self.assertEqual(results["default"], results["listen"])
            self.assertEqual(results["default"], results["name"])
