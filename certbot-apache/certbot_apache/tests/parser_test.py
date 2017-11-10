"""Tests for certbot_apache.parser."""
import os
import shutil
import unittest

import augeas
import mock

from certbot import errors

from certbot_apache.tests import util


class BasicParserTest(util.ParserTest):
    """Apache Parser Test."""

    def setUp(self):  # pylint: disable=arguments-differ
        super(BasicParserTest, self).setUp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir)
        shutil.rmtree(self.config_dir)
        shutil.rmtree(self.work_dir)

    def test_find_config_root_no_root(self):
        # pylint: disable=protected-access
        os.remove(self.parser.loc["root"])
        self.assertRaises(
            errors.NoInstallationError, self.parser._find_config_root)

    def test_parse_file(self):
        """Test parse_file.

        certbot.conf is chosen as the test file as it will not be
        included during the normal course of execution.

        """
        file_path = os.path.join(
            self.config_path, "not-parsed-by-default", "certbot.conf")

        self.parser.parse_file(file_path)  # pylint: disable=protected-access

        # search for the httpd incl
        matches = self.parser.aug.match(
            "/augeas/load/Httpd/incl [. ='%s']" % file_path)

        self.assertTrue(matches)

    def test_find_dir(self):
        test = self.parser.find_dir("Listen", "80")
        # This will only look in enabled hosts
        test2 = self.parser.find_dir("documentroot")

        self.assertEqual(len(test), 1)
        self.assertEqual(len(test2), 7)

    def test_add_dir(self):
        aug_default = "/files" + self.parser.loc["default"]
        self.parser.add_dir(aug_default, "AddDirective", "test")

        self.assertTrue(
            self.parser.find_dir("AddDirective", "test", aug_default))

        self.parser.add_dir(aug_default, "AddList", ["1", "2", "3", "4"])
        matches = self.parser.find_dir("AddList", None, aug_default)
        for i, match in enumerate(matches):
            self.assertEqual(self.parser.aug.get(match), str(i + 1))

    def test_empty_arg(self):
        self.assertEquals(None,
                          self.parser.get_arg("/files/whatever/nonexistent"))

    def test_add_dir_to_ifmodssl(self):
        """test add_dir_to_ifmodssl.

        Path must be valid before attempting to add to augeas

        """
        from certbot_apache.parser import get_aug_path
        # This makes sure that find_dir will work
        self.parser.modules.add("mod_ssl.c")

        self.parser.add_dir_to_ifmodssl(
            get_aug_path(self.parser.loc["default"]),
            "FakeDirective", ["123"])

        matches = self.parser.find_dir("FakeDirective", "123")

        self.assertEqual(len(matches), 1)
        self.assertTrue("IfModule" in matches[0])

    def test_add_dir_to_ifmodssl_multiple(self):
        from certbot_apache.parser import get_aug_path
        # This makes sure that find_dir will work
        self.parser.modules.add("mod_ssl.c")

        self.parser.add_dir_to_ifmodssl(
            get_aug_path(self.parser.loc["default"]),
            "FakeDirective", ["123", "456", "789"])

        matches = self.parser.find_dir("FakeDirective")

        self.assertEqual(len(matches), 3)
        self.assertTrue("IfModule" in matches[0])

    def test_get_aug_path(self):
        from certbot_apache.parser import get_aug_path
        self.assertEqual("/files/etc/apache", get_aug_path("/etc/apache"))

    def test_set_locations(self):
        with mock.patch("certbot_apache.parser.os.path") as mock_path:

            mock_path.isfile.side_effect = [False, False]

            # pylint: disable=protected-access
            results = self.parser._set_locations()

            self.assertEqual(results["default"], results["listen"])
            self.assertEqual(results["default"], results["name"])

    @mock.patch("certbot_apache.parser.ApacheParser.find_dir")
    @mock.patch("certbot_apache.parser.ApacheParser.get_arg")
    def test_parse_modules_bad_syntax(self, mock_arg, mock_find):
        mock_find.return_value = ["1", "2", "3", "4", "5", "6", "7", "8"]
        mock_arg.return_value = None
        with mock.patch("certbot_apache.parser.logger") as mock_logger:
            self.parser.parse_modules()
            # Make sure that we got None return value and logged the file
            self.assertTrue(mock_logger.debug.called)

    @mock.patch("certbot_apache.parser.ApacheParser._get_runtime_cfg")
    def test_update_runtime_variables(self, mock_cfg):
        define_val = (
            'ServerRoot: "/etc/apache2"\n'
            'Main DocumentRoot: "/var/www"\n'
            'Main ErrorLog: "/var/log/apache2/error.log"\n'
            'Mutex ssl-stapling: using_defaults\n'
            'Mutex ssl-cache: using_defaults\n'
            'Mutex default: dir="/var/lock/apache2" mechanism=fcntl\n'
            'Mutex watchdog-callback: using_defaults\n'
            'PidFile: "/var/run/apache2/apache2.pid"\n'
            'Define: TEST\n'
            'Define: DUMP_RUN_CFG\n'
            'Define: U_MICH\n'
            'Define: TLS=443\n'
            'Define: example_path=Documents/path\n'
            'User: name="www-data" id=33 not_used\n'
            'Group: name="www-data" id=33 not_used\n'
        )
        inc_val = (
            'Included configuration files:\n'
            '  (*) /etc/apache2/apache2.conf\n'
            '    (146) /etc/apache2/mods-enabled/access_compat.load\n'
            '    (146) /etc/apache2/mods-enabled/alias.load\n'
            '    (146) /etc/apache2/mods-enabled/auth_basic.load\n'
            '    (146) /etc/apache2/mods-enabled/authn_core.load\n'
            '    (146) /etc/apache2/mods-enabled/authn_file.load\n'
            '    (146) /etc/apache2/mods-enabled/authz_core.load\n'
            '    (146) /etc/apache2/mods-enabled/authz_host.load\n'
            '    (146) /etc/apache2/mods-enabled/authz_user.load\n'
            '    (146) /etc/apache2/mods-enabled/autoindex.load\n'
            '    (146) /etc/apache2/mods-enabled/deflate.load\n'
            '    (146) /etc/apache2/mods-enabled/dir.load\n'
            '    (146) /etc/apache2/mods-enabled/env.load\n'
            '    (146) /etc/apache2/mods-enabled/filter.load\n'
            '    (146) /etc/apache2/mods-enabled/mime.load\n'
            '    (146) /etc/apache2/mods-enabled/mpm_event.load\n'
            '    (146) /etc/apache2/mods-enabled/negotiation.load\n'
            '    (146) /etc/apache2/mods-enabled/reqtimeout.load\n'
            '    (146) /etc/apache2/mods-enabled/setenvif.load\n'
            '    (146) /etc/apache2/mods-enabled/socache_shmcb.load\n'
            '    (146) /etc/apache2/mods-enabled/ssl.load\n'
            '    (146) /etc/apache2/mods-enabled/status.load\n'
            '    (147) /etc/apache2/mods-enabled/alias.conf\n'
            '    (147) /etc/apache2/mods-enabled/autoindex.conf\n'
            '    (147) /etc/apache2/mods-enabled/deflate.conf\n'
        )
        mod_val = (
            'Loaded Modules:\n'
            ' core_module (static)\n'
            ' so_module (static)\n'
            ' watchdog_module (static)\n'
            ' http_module (static)\n'
            ' log_config_module (static)\n'
            ' logio_module (static)\n'
            ' version_module (static)\n'
            ' unixd_module (static)\n'
            ' access_compat_module (shared)\n'
            ' alias_module (shared)\n'
            ' auth_basic_module (shared)\n'
            ' authn_core_module (shared)\n'
            ' authn_file_module (shared)\n'
            ' authz_core_module (shared)\n'
            ' authz_host_module (shared)\n'
            ' authz_user_module (shared)\n'
            ' autoindex_module (shared)\n'
            ' deflate_module (shared)\n'
            ' dir_module (shared)\n'
            ' env_module (shared)\n'
            ' filter_module (shared)\n'
            ' mime_module (shared)\n'
            ' mpm_event_module (shared)\n'
            ' negotiation_module (shared)\n'
            ' reqtimeout_module (shared)\n'
            ' setenvif_module (shared)\n'
            ' socache_shmcb_module (shared)\n'
            ' ssl_module (shared)\n'
            ' status_module (shared)\n'
        )

        def mock_get_vars(cmd):
            """Mock command output"""
            if cmd[-1] == "DUMP_RUN_CFG":
                return define_val
            elif cmd[-1] == "DUMP_INCLUDES":
                return inc_val
            elif cmd[-1] == "DUMP_MODULES":
                return mod_val

        mock_cfg.side_effect = mock_get_vars

        expected_vars = {"TEST": "", "U_MICH": "", "TLS": "443",
                         "example_path": "Documents/path"}

        self.parser.modules = set()
        with mock.patch(
            "certbot_apache.parser.ApacheParser.parse_file") as mock_parse:
            self.parser.update_runtime_variables()
            self.assertEqual(self.parser.variables, expected_vars)
            self.assertEqual(len(self.parser.modules), 58)
            # None of the includes in inc_val should be in parsed paths.
            # Make sure we tried to include them all.
            self.assertEqual(mock_parse.call_count, 25)

    @mock.patch("certbot_apache.parser.ApacheParser._get_runtime_cfg")
    def test_update_runtime_variables_alt_values(self, mock_cfg):
        inc_val = (
            'Included configuration files:\n'
            '  (*) {0}\n'
            '    (146) /etc/apache2/mods-enabled/access_compat.load\n'
            '    (146) {1}/mods-enabled/alias.load\n'
        ).format(self.parser.loc["root"],
                 os.path.dirname(self.parser.loc["root"]))

        mock_cfg.return_value = inc_val
        self.parser.modules = set()

        with mock.patch(
            "certbot_apache.parser.ApacheParser.parse_file") as mock_parse:
            self.parser.update_runtime_variables()
            # No matching modules should have been found
            self.assertEqual(len(self.parser.modules), 0)
            # Only one of the three includes do not exist in already parsed
            # path derived from root configuration Include statements
            self.assertEqual(mock_parse.call_count, 1)

    @mock.patch("certbot_apache.parser.ApacheParser._get_runtime_cfg")
    def test_update_runtime_vars_bad_output(self, mock_cfg):
        mock_cfg.return_value = "Define: TLS=443=24"
        self.parser.update_runtime_variables()

        mock_cfg.return_value = "Define: DUMP_RUN_CFG\nDefine: TLS=443=24"
        self.assertRaises(
            errors.PluginError, self.parser.update_runtime_variables)

    @mock.patch("certbot_apache.constants.os_constant")
    @mock.patch("certbot_apache.parser.subprocess.Popen")
    def test_update_runtime_vars_bad_ctl(self, mock_popen, mock_const):
        mock_popen.side_effect = OSError
        mock_const.return_value = "nonexistent"
        self.assertRaises(
            errors.MisconfigurationError,
            self.parser.update_runtime_variables)

    @mock.patch("certbot_apache.parser.subprocess.Popen")
    def test_update_runtime_vars_bad_exit(self, mock_popen):
        mock_popen().communicate.return_value = ("", "")
        mock_popen.returncode = -1
        self.assertRaises(
            errors.MisconfigurationError,
            self.parser.update_runtime_variables)


class ParserInitTest(util.ApacheTest):
    def setUp(self):  # pylint: disable=arguments-differ
        super(ParserInitTest, self).setUp()
        self.aug = augeas.Augeas(
            flags=augeas.Augeas.NONE | augeas.Augeas.NO_MODL_AUTOLOAD)

    def tearDown(self):
        shutil.rmtree(self.temp_dir)
        shutil.rmtree(self.config_dir)
        shutil.rmtree(self.work_dir)

    @mock.patch("certbot_apache.parser.ApacheParser._get_runtime_cfg")
    def test_unparseable(self, mock_cfg):
        from certbot_apache.parser import ApacheParser
        mock_cfg.return_value = ('Define: TEST')
        self.assertRaises(
            errors.PluginError,
            ApacheParser, self.aug, os.path.relpath(self.config_path),
            "/dummy/vhostpath", version=(2, 2, 22), configurator=self.config)

    def test_root_normalized(self):
        from certbot_apache.parser import ApacheParser

        with mock.patch("certbot_apache.parser.ApacheParser."
                        "update_runtime_variables"):
            path = os.path.join(
                self.temp_dir,
                "debian_apache_2_4/////multiple_vhosts/../multiple_vhosts/apache2")

            parser = ApacheParser(self.aug, path,
                                  "/dummy/vhostpath", configurator=self.config)

        self.assertEqual(parser.root, self.config_path)

    def test_root_absolute(self):
        from certbot_apache.parser import ApacheParser
        with mock.patch("certbot_apache.parser.ApacheParser."
                        "update_runtime_variables"):
            parser = ApacheParser(
                self.aug, os.path.relpath(self.config_path),
                "/dummy/vhostpath", configurator=self.config)

        self.assertEqual(parser.root, self.config_path)

    def test_root_no_trailing_slash(self):
        from certbot_apache.parser import ApacheParser
        with mock.patch("certbot_apache.parser.ApacheParser."
                        "update_runtime_variables"):
            parser = ApacheParser(
                self.aug, self.config_path + os.path.sep,
                "/dummy/vhostpath", configurator=self.config)
        self.assertEqual(parser.root, self.config_path)


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
