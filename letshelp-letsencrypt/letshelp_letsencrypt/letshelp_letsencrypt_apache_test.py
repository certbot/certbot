"""Tests for letshelp.letshelp_letsencrypt_apache.py"""
import argparse
import functools
import os
import pkg_resources
import tempfile
import unittest

import mock

import letshelp_letsencrypt.letshelp_letsencrypt_apache as letshelp_le_apache


_PASSWD_FILE = pkg_resources.resource_filename(__name__, "testdata/passwd")
_CONF_FILE = pkg_resources.resource_filename(
    __name__, "testdata/conf-available/charset.conf")


_MODULE_NAME = "letshelp_letsencrypt.letshelp_letsencrypt_apache"


_COMPILE_SETTINGS = """Server version: Apache/2.4.10 (Debian)
Server built:   Mar 15 2015 09:51:43
Server's Module Magic Number: 20120211:37
Server loaded:  APR 1.5.1, APR-UTIL 1.5.4
Compiled using: APR 1.5.1, APR-UTIL 1.5.4
Architecture:   64-bit
Server MPM:     event
  threaded:     yes (fixed thread count)
    forked:     yes (variable process count)
Server compiled with....
 -D APR_HAS_SENDFILE
 -D APR_HAS_MMAP
 -D APR_HAVE_IPV6 (IPv4-mapped addresses enabled)
 -D APR_USE_SYSVSEM_SERIALIZE
 -D APR_USE_PTHREAD_SERIALIZE
 -D SINGLE_LISTEN_UNSERIALIZED_ACCEPT
 -D APR_HAS_OTHER_CHILD
 -D AP_HAVE_RELIABLE_PIPED_LOGS
 -D DYNAMIC_MODULE_LIMIT=256
 -D HTTPD_ROOT="/etc/apache2"
 -D SUEXEC_BIN="/usr/lib/apache2/suexec"
 -D DEFAULT_PIDLOG="/var/run/apache2.pid"
 -D DEFAULT_SCOREBOARD="logs/apache_runtime_status"
 -D DEFAULT_ERRORLOG="logs/error_log"
 -D AP_TYPES_CONFIG_FILE="mime.types"
 -D SERVER_CONFIG_FILE="apache2.conf"

"""


class LetsHelpApacheTest(unittest.TestCase):
    @mock.patch(_MODULE_NAME + ".copy_config")
    def test_make_and_verify_selection(self, mock_copy_config):
        mock_copy_config.return_value = ["apache2.conf"], ["apache2"]

        with mock.patch("__builtin__.raw_input") as mock_input:
            with mock.patch(_MODULE_NAME + ".sys.stdout"):
                mock_input.side_effect = ["Yes", "No"]
                letshelp_le_apache.make_and_verify_selection("root", "temp")
                self.assertRaises(
                    SystemExit, letshelp_le_apache.make_and_verify_selection,
                    "server_root", "temp_dir")

    def test_copy_config(self):
        tempdir = tempfile.mkdtemp()
        server_root = pkg_resources.resource_filename(__name__, "testdata")
        letshelp_le_apache.copy_config(server_root, tempdir)

        temp_testdata = os.path.join(tempdir, "testdata")
        self.assertFalse(os.path.exists(os.path.join(temp_testdata, "passwd")))
        self.assertTrue(os.path.exists(os.path.join(
            temp_testdata, "conf-available", "charset.conf")))
        self.assertTrue(os.path.exists(os.path.join(
            temp_testdata, "conf-enabled", "charset.conf")))

    def test_copy_file_without_comments(self):
        dest = tempfile.mkstemp()[1]
        letshelp_le_apache.copy_file_without_comments(_PASSWD_FILE, dest)

        with open(_PASSWD_FILE) as original:
            with open(dest) as copy:
                for original_line, copied_line in zip(original, copy):
                    self.assertEqual(original_line, copied_line)

    @mock.patch(_MODULE_NAME + ".subprocess.check_output")
    def test_safe_config_file(self, mock_check_output):
        mock_check_output.return_value = "PEM RSA private key"
        self.assertFalse(letshelp_le_apache.safe_config_file("filename"))

        mock_check_output.return_value = "ASCII text"
        self.assertFalse(letshelp_le_apache.safe_config_file(_PASSWD_FILE))
        self.assertTrue(letshelp_le_apache.safe_config_file(_CONF_FILE))

    @mock.patch(_MODULE_NAME + ".subprocess.check_output")
    def test_tempdir(self, mock_check_output):
        mock_check_output.side_effect = ["version", "modules", "vhosts"]
        args = argparse.Namespace()
        args.apache_ctl = "apache_ctl"
        args.config_file = "config_file"
        args.server_root = "server_root"

        tempdir = letshelp_le_apache.setup_tempdir(args)

        with open(os.path.join(tempdir, "config_file")) as config_fd:
            self.assertEqual(config_fd.read(), args.config_file + "\n")

        with open(os.path.join(tempdir, "version")) as version_fd:
            self.assertEqual(version_fd.read(), "version")

        with open(os.path.join(tempdir, "modules")) as modules_fd:
            self.assertEqual(modules_fd.read(), "modules")

        with open(os.path.join(tempdir, "vhosts")) as vhosts_fd:
            self.assertEqual(vhosts_fd.read(), "vhosts")

    @mock.patch(_MODULE_NAME + ".subprocess.check_output")
    def test_locate_config(self, mock_check_output):
        mock_check_output.side_effect = [OSError, "bad_output",
                                         _COMPILE_SETTINGS,]

        self.assertRaises(
            SystemExit, letshelp_le_apache.locate_config, "ctl")
        self.assertRaises(
            SystemExit, letshelp_le_apache.locate_config, "ctl")
        server_root, config_file = letshelp_le_apache.locate_config("ctl")
        self.assertEqual(server_root, "/etc/apache2")
        self.assertEqual(config_file, "apache2.conf")

    @mock.patch(_MODULE_NAME + ".argparse")
    def test_get_args(self, mock_argparse):
        argv = ["-d", "/etc/apache2"]
        mock_argparse.ArgumentParser.return_value = _create_mock_parser(argv)
        self.assertRaises(SystemExit, letshelp_le_apache.get_args)

        server_root = "/etc/apache2"
        config_file = server_root + "/apache2.conf"
        argv = ["-d", server_root, "-f", config_file]
        mock_argparse.ArgumentParser.return_value = _create_mock_parser(argv)
        args = letshelp_le_apache.get_args()
        self.assertEqual(args.apache_ctl, "apachectl")
        self.assertEqual(args.server_root, server_root)
        self.assertEqual(args.config_file, os.path.basename(config_file))

        server_root = "/etc/apache2"
        config_file = "/etc/httpd/httpd.conf"
        argv = ["-d", server_root, "-f", config_file]
        mock_argparse.ArgumentParser.return_value = _create_mock_parser(argv)
        self.assertRaises(SystemExit, letshelp_le_apache.get_args)


def _create_mock_parser(argv):
    parser = argparse.ArgumentParser()
    mock_parser = mock.MagicMock()
    mock_parser.add_argument = parser.add_argument
    mock_parser.parse_args = functools.partial(parser.parse_args, argv)

    return mock_parser


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
