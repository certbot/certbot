"""Tests for letshelp.letshelp_certbot_apache.py"""
import argparse
import functools
import os
import pkg_resources
import subprocess
import tarfile
import tempfile
import unittest

import mock

import letshelp_certbot.apache as letshelp_le_apache


_PARTIAL_CONF_PATH = os.path.join("mods-available", "ssl.load")
_PARTIAL_LINK_PATH = os.path.join("mods-enabled", "ssl.load")
_CONFIG_FILE = pkg_resources.resource_filename(
    __name__, os.path.join("testdata", _PARTIAL_CONF_PATH))
_PASSWD_FILE = pkg_resources.resource_filename(
    __name__, os.path.join("testdata", "uncommonly_named_p4sswd"))
_KEY_FILE = pkg_resources.resource_filename(
    __name__, os.path.join("testdata", "uncommonly_named_k3y"))
_SECRET_FILE = pkg_resources.resource_filename(
    __name__, os.path.join("testdata", "super_secret_file.txt"))


_MODULE_NAME = "letshelp_certbot.apache"


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
        mock_copy_config.return_value = (["apache2.conf"], ["apache2"])

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
        self.assertFalse(os.path.exists(os.path.join(
            temp_testdata, os.path.basename(_PASSWD_FILE))))
        self.assertFalse(os.path.exists(os.path.join(
            temp_testdata, os.path.basename(_KEY_FILE))))
        self.assertFalse(os.path.exists(os.path.join(
            temp_testdata, os.path.basename(_SECRET_FILE))))
        self.assertTrue(os.path.exists(os.path.join(
            temp_testdata, _PARTIAL_CONF_PATH)))
        self.assertTrue(os.path.exists(os.path.join(
            temp_testdata, _PARTIAL_LINK_PATH)))

    def test_copy_file_without_comments(self):
        dest = tempfile.mkstemp()[1]
        letshelp_le_apache.copy_file_without_comments(_PASSWD_FILE, dest)

        with open(_PASSWD_FILE) as original:
            with open(dest) as copy:
                for original_line, copied_line in zip(original, copy):
                    self.assertEqual(original_line, copied_line)

    @mock.patch(_MODULE_NAME + ".subprocess.Popen")
    def test_safe_config_file(self, mock_popen):
        mock_popen().communicate.return_value = ("PEM RSA private key", None)
        self.assertFalse(letshelp_le_apache.safe_config_file("filename"))

        mock_popen().communicate.return_value = ("ASCII text", None)
        self.assertFalse(letshelp_le_apache.safe_config_file(_PASSWD_FILE))
        self.assertFalse(letshelp_le_apache.safe_config_file(_KEY_FILE))
        self.assertFalse(letshelp_le_apache.safe_config_file(_SECRET_FILE))
        self.assertTrue(letshelp_le_apache.safe_config_file(_CONFIG_FILE))

    @mock.patch(_MODULE_NAME + ".subprocess.Popen")
    def test_tempdir(self, mock_popen):
        mock_popen().communicate.side_effect = [
            ("version", None), ("modules", None), ("vhosts", None)]
        args = _get_args()

        tempdir = letshelp_le_apache.setup_tempdir(args)

        with open(os.path.join(tempdir, "config_file")) as config_fd:
            self.assertEqual(config_fd.read(), args.config_file + "\n")

        with open(os.path.join(tempdir, "version")) as version_fd:
            self.assertEqual(version_fd.read(), "version")

        with open(os.path.join(tempdir, "modules")) as modules_fd:
            self.assertEqual(modules_fd.read(), "modules")

        with open(os.path.join(tempdir, "vhosts")) as vhosts_fd:
            self.assertEqual(vhosts_fd.read(), "vhosts")

    @mock.patch(_MODULE_NAME + ".subprocess.check_call")
    def test_verify_config(self, mock_check_call):
        args = _get_args()
        mock_check_call.side_effect = [
            None, OSError, subprocess.CalledProcessError(1, "apachectl")]

        letshelp_le_apache.verify_config(args)
        self.assertRaises(SystemExit, letshelp_le_apache.verify_config, args)
        self.assertRaises(SystemExit, letshelp_le_apache.verify_config, args)

    @mock.patch(_MODULE_NAME + ".subprocess.Popen")
    def test_locate_config(self, mock_popen):
        mock_popen().communicate.side_effect = [
            OSError, ("bad_output", None), (_COMPILE_SETTINGS, None)]

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

    def test_main_with_args(self):
        with mock.patch(_MODULE_NAME + ".get_args"):
            self._test_main_common()

    def test_main_without_args(self):
        with mock.patch(_MODULE_NAME + ".get_args") as get_args:
            args = _get_args()
            server_root, config_file = args.server_root, args.config_file
            args.server_root = args.config_file = None
            get_args.return_value = args
            with mock.patch(_MODULE_NAME + ".locate_config") as locate:
                locate.return_value = (server_root, config_file)
                self._test_main_common()

    def _test_main_common(self):
        with mock.patch(_MODULE_NAME + ".verify_config"):
            with mock.patch(_MODULE_NAME + ".setup_tempdir") as mock_setup:
                tempdir_path = tempfile.mkdtemp()
                mock_setup.return_value = tempdir_path
                with mock.patch(_MODULE_NAME + ".make_and_verify_selection"):
                    testdir_basename = "test"
                    os.mkdir(os.path.join(tempdir_path, testdir_basename))

                    letshelp_le_apache.main()

                    tar = tarfile.open(os.path.join(
                        tempdir_path, "config.tar.gz"))

                    tempdir = tar.next()
                    self.assertTrue(tempdir.isdir())
                    self.assertEqual(tempdir.name, ".")

                    testdir = tar.next()
                    self.assertTrue(testdir.isdir())
                    self.assertEqual(os.path.basename(testdir.name),
                                     testdir_basename)

                    self.assertEqual(tar.next(), None)


def _create_mock_parser(argv):
    parser = argparse.ArgumentParser()
    mock_parser = mock.MagicMock()
    mock_parser.add_argument = parser.add_argument
    mock_parser.parse_args = functools.partial(parser.parse_args, argv)

    return mock_parser


def _get_args():
    args = argparse.Namespace()
    args.apache_ctl = "apache_ctl"
    args.config_file = "config_file"
    args.server_root = "server_root"

    return args


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
