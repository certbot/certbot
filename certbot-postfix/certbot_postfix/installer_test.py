"""Tests for certbot_postfix.installer."""
import functools
import os
import subprocess
import unittest

import mock

from certbot import errors
from certbot.tests import util as certbot_test_util


class InstallerTest(certbot_test_util.ConfigTestCase):

    def setUp(self):
        super(InstallerTest, self).setUp()
        self.config.postfix_ctl = "postfix"
        self.config.postfix_config_dir = self.tempdir
        self.config.postfix_config_utility = "postconf"
        self.mock_postfix = MockPostfix(self.tempdir,
                                        {"mail_version": "3.1.4"})

    def test_add_parser_arguments(self):
        options = set(('ctl', 'config-dir', 'config-utility',))
        mock_add = mock.MagicMock()

        from certbot_postfix import installer
        installer.Installer.add_parser_arguments(mock_add)

        for call in mock_add.call_args_list:
            self.assertTrue(call[0][0] in options)

    def test_no_postconf_prepare(self):
        installer = self._create_installer()

        installer_path = "certbot_postfix.installer"
        exe_exists_path = installer_path + ".certbot_util.exe_exists"
        path_surgery_path = installer_path + ".plugins_util.path_surgery"

        with mock.patch(path_surgery_path, return_value=False):
            with mock.patch(exe_exists_path, return_value=False):
                self.assertRaises(errors.NoInstallationError,
                                  installer.prepare)

    def test_set_config_dir(self):
        self.config.postfix_config_dir = os.path.join(self.tempdir, "subdir")
        os.mkdir(self.config.postfix_config_dir)
        installer = self._create_installer()

        expected = self.config.postfix_config_dir
        self.config.postfix_config_dir = None

        self.mock_postfix(
            "postconf config_directory={0}".format(expected).split())
        exe_exists_path = "certbot_postfix.installer.certbot_util.exe_exists"
        with mock.patch(exe_exists_path, return_value=True):
            self._mock_postfix_and_call(installer.prepare)
        self.assertEqual(installer.config_dir, expected)

    @mock.patch("certbot_postfix.installer.certbot_util.exe_exists")
    def test_old_version(self, mock_exe_exists):
        installer = self._create_installer()
        mock_exe_exists.return_value = True
        self.mock_postfix("postconf mail_version=0.0.1".split())
        self._mock_postfix_and_call(
            self.assertRaises, errors.NotSupportedError, installer.prepare)

    def test_lock_error(self):
        assert_raises = functools.partial(self.assertRaises,
                                          errors.PluginError,
                                          self._create_prepared_installer)
        certbot_test_util.lock_and_call(assert_raises, self.tempdir)

    def test_more_info(self):
        installer = self._create_prepared_installer()
        version = "3.1.4"
        self.mock_postfix("postconf mail_version={0}".format(version).split())

        output = self._mock_postfix_and_call(installer.more_info)
        self.assertTrue("Postfix" in output)
        self.assertTrue(self.tempdir in output)
        self.assertTrue(version in output)

    def test_get_all_names(self):
        installer = self._create_prepared_installer()
        self.mock_postfix("postconf mydomain=example.org "
                          "myhostname=mail.example.org "
                          "myorigin=example.org".split())
        result = self._mock_postfix_and_call(installer.get_all_names)
        self.assertTrue("example.org" in result)
        self.assertTrue("mail.example.org" in result)

    def test_deploy_and_save(self):
        key_path = "key_path"
        fullchain_path = "fullchain_path"
        installer = self._create_prepared_installer()

        for i, domain in enumerate(("example.org", "mail.example.org",)):
            self._mock_postfix_and_call(
                installer.deploy_cert, domain, "unused",
                key_path, "unused", fullchain_path)
            if i:
                installer.save("noop")
            else:
                self._mock_postfix_and_call(installer.save, "real save")

        expected_config = {"smtpd_tls_cert_file": fullchain_path,
                           "smtpd_tls_key_file": key_path,
                           "smtpd_use_tls": "yes"}
        for key, value in expected_config.items():
            postconf_output = self.mock_postfix(["postconf", key])
            self.assertEqual("{0} = {1}\n".format(key, value), postconf_output)

    def test_enhance(self):
        self.assertRaises(errors.PluginError,
                          self._create_prepared_installer().enhance,
                          "example.org", "redirect")

    def test_supported_enhancements(self):
        self.assertEqual(
            self._create_prepared_installer().supported_enhancements(), [])

    @mock.patch("certbot_postfix.installer.subprocess.check_call")
    def test_config_test_failure(self, mock_check_call):
        installer = self._create_prepared_installer()
        mock_check_call.side_effect = subprocess.CalledProcessError(42, "foo")
        self.assertRaises(errors.MisconfigurationError, installer.config_test)

    @mock.patch("certbot_postfix.installer.subprocess.check_call")
    def test_postfix_reload_failure(self, mock_check_call):
        installer = self._create_prepared_installer()
        mock_check_call.side_effect = [
            None, subprocess.CalledProcessError(42, "foo")
        ]
        self.assertRaises(errors.PluginError, installer.restart)

    def test_postfix_reload_success(self):
        with mock.patch("certbot_postfix.installer.subprocess.check_call"):
            installer = self._create_prepared_installer()
            installer.restart()

    @mock.patch("certbot_postfix.installer.subprocess.check_call")
    def test_postfix_start_failure(self, mock_check_call):
        installer = self._create_prepared_installer()
        mock_check_call.side_effect = subprocess.CalledProcessError(42, "foo")
        self.assertRaises(errors.PluginError, installer.restart)

    @mock.patch("certbot_postfix.installer.subprocess.check_call")
    def test_postfix_start_success(self, mock_check_call):
        installer = self._create_prepared_installer()
        mock_check_call.side_effect = [
            subprocess.CalledProcessError(42, "foo"), None
        ]
        installer.restart()

    def test_get_config_var_success(self):
        self.config.postfix_config_dir = None

        command = self._test_get_config_var_success_common('foo', False)
        self.assertFalse("-c" in command)
        self.assertFalse("-d" in command)

    def test_get_config_var_success_with_config(self):
        command = self._test_get_config_var_success_common('foo', False)
        self.assertTrue("-c" in command)
        self.assertFalse("-d" in command)

    def test_get_config_var_success_with_default(self):
        self.config.postfix_config_dir = None

        command = self._test_get_config_var_success_common('foo', True)
        self.assertFalse("-c" in command)
        self.assertTrue("-d" in command)

    @mock.patch("certbot_postfix.installer.util.check_output")
    def test_get_config_var_failure(self, mock_check_output):
        mock_check_output.side_effect = subprocess.CalledProcessError(42,
                                                                      "foo")
        installer = self._create_installer()
        self.assertRaises(errors.PluginError, installer.get_config_var, "foo")

    @mock.patch("certbot_postfix.installer.util.check_output")
    def test_get_config_var_unexpected_output(self, mock_check_output):
        self.config.postfix_config_dir = None
        mock_check_output.return_value = "foo"

        installer = self._create_installer()
        self.assertRaises(errors.PluginError, installer.get_config_var, "foo")

    def _test_get_config_var_success_common(self, name, default):
        installer = self._create_installer()

        check_output_path = "certbot_postfix.installer.util.check_output"
        with mock.patch(check_output_path) as mock_check_output:
            value = "bar"
            mock_check_output.return_value = name + " = " + value
            self.assertEqual(installer.get_config_var(name, default), value)

        return mock_check_output.call_args[0][0]

    def _create_prepared_installer(self):
        """Creates and returns a new prepared Postfix Installer.

        Calls in prepare() are mocked out so the Postfix version check
        is successful.

        :returns: a prepared Postfix installer
        :rtype: certbot_postfix.installer.Installer

        """
        installer = self._create_installer()

        exe_exists_path = "certbot_postfix.installer.certbot_util.exe_exists"
        with mock.patch(exe_exists_path, return_value=True):
            self._mock_postfix_and_call(installer.prepare)

        return installer

    def _create_installer(self):
        """Creates and returns a new Postfix Installer.

        :returns: a new Postfix installer
        :rtype: certbot_postfix.installer.Installer

        """
        name = "postfix"

        from certbot_postfix import installer
        return installer.Installer(self.config, name)

    def _mock_postfix_and_call(self, func, *args, **kwargs):
        """Calls func with mocked responses from Postfix utilities.

        :param callable func: function to call with mocked args
        :param tuple args: positional arguments to func
        :param dict kwargs: keyword arguments to func

        :returns: the return value of func

        """
        check_call_path = "certbot_postfix.installer.subprocess.check_call"
        check_output_path = "certbot_postfix.installer.util.check_output"

        with mock.patch(check_call_path) as mock_check_call:
            mock_check_call.side_effect = self.mock_postfix
            with mock.patch(check_output_path) as mock_check_output:
                mock_check_output.side_effect = self.mock_postfix
                return func(*args, **kwargs)


class MockPostfix(object):
    """A callable to mimic Postfix command line utilities.

    This is best used a side effect to a mock object. All calls to
    'postfix' are noops. For calls to 'postconf', values that are set in
    the constructor or through mocked out runs of postconf are
    remembered and properly returned if the installer attempts to fetch
    the value. If the Postfix installer attempts to obtain a value that
    hasn't yet been set, a dummy value is returned.

    :ivar str config_path: path to Postfix main.cf file

    """
    def __init__(self, config_dir, initial_values=None):
        """Create Postfix configuration.

        :param str config_dir: path for Postfix config dir
        :param dict initial_values: initial Postfix config values

        """
        if initial_values is None:
            initial_values = {}
        initial_values["config_directory"] = config_dir

        self.config_path = os.path.join(config_dir, "main.cf")
        self._write_config(initial_values)

    def __call__(self, args, *unused_args, **unused_kwargs):
        cmd = os.path.basename(args[0])
        if cmd == "postfix":
            return
        elif cmd != "postconf":
            assert False, "Unexpected command '{0}'".format(''.join(args))

        config = self._read_config()
        output = []

        skip = False
        for arg in args[1:]:
            if skip:
                skip = False
            elif arg[0] == "-":
                if arg == "-c":
                    skip = True
            elif "=" in arg:
                name, _, value = arg.partition("=")
                config[name] = value
            else:
                output.append("{0} = {1}\n".format(arg, config.get(arg, "")))

        self._write_config(config)
        return "\n".join(output)

    def _read_config(self):
        config = {}
        with open(self.config_path) as f:
            for line in f:
                key, _, value = line.strip().partition(" = ")
                config[key] = value

        return config

    def _write_config(self, config):
        with open(self.config_path, "w") as f:
            f.writelines("{0} = {1}\n".format(key, value)
                         for key, value in config.items())


if __name__ == '__main__':
    unittest.main()  # pragma: no cover
