"""Tests for certbot_postfix.installer."""
import functools
import os
import shutil
import subprocess
import unittest

import mock

from certbot import errors
from certbot.tests import util as certbot_test_util


class InstallerTest(certbot_test_util.ConfigTestCase):
    # pylint: disable=too-many-public-methods

    def setUp(self):
        super(InstallerTest, self).setUp()
        self.config.postfix_ctl = "postfix"
        self.config.postfix_config_dir = self.tempdir
        self.config.postfix_config_utility = "postconf"
        self.config.postfix_policy_file = os.path.join(self.tempdir, "config.json")
        shutil.copyfile("test_data/config.json", self.config.postfix_policy_file)
    
        self.mock_postfix = MockPostfix()# MockPostfix(self.tempdir, {"mail_version": "3.1.4"})
        self.mock_postconf = MockPostconf(self.tempdir, {"mail_version": "3.1.4"})

    def test_add_parser_arguments(self):
        options = set(('ctl', 'config-dir', 'config-utility', 'policy-file',))
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

        # self.mock_postfix.set_value("config_directory", expected)
        self.mock_postconf.set("config_directory", expected)
        exe_exists_path = "certbot_postfix.installer.certbot_util.exe_exists"
        with mock.patch(exe_exists_path, return_value=True):
            self._mock_postfix_and_call(installer.prepare)
        self.assertEqual(installer.config_dir, expected)

    @mock.patch("certbot_postfix.installer.certbot_util.exe_exists")
    def test_old_version(self, mock_exe_exists):
        installer = self._create_installer()
        mock_exe_exists.return_value = True
        self.mock_postconf.set("mail_version", "0.0.1")
        self._mock_postfix_and_call(
            self.assertRaises, errors.NotSupportedError, installer.prepare)

    def test_lock_error(self):
        assert_raises = functools.partial(self.assertRaises,
                                          errors.PluginError,
                                          self._create_prepared_installer)
        certbot_test_util.lock_and_call(assert_raises, self.tempdir)

    def test_more_info(self):
        installer = self._create_prepared_installer()
        version = "3.1.2"
        # self.mock_postfix.set_value("mail_version", version)
        self.mock_postconf.set("mail_version", version)

        output = self._mock_postfix_and_call(installer.more_info)
        self.assertTrue("Postfix" in output)
        self.assertTrue(self.tempdir in output)
        self.assertTrue(version in output)

    def test_get_all_names(self):
        config = {"mydomain": "example.org",
                  "myhostname": "mail.example.org",
                  "myorigin": "example.org"}
        for name, value in config.items():
            # self.mock_postfix.set_value(name, value)
            self.mock_postconf.set(name, value)

        installer = self._create_prepared_installer()
        result = self._mock_postfix_and_call(installer.get_all_names)
        self.assertEqual(result, set(config.values()))

    def test_deploy(self):
        installer = self._create_prepared_installer()

        def deploy_cert(domain):
            """Calls deploy_cert for the given domain.

            :param str domain: domain to deploy cert for

            """
            installer.deploy_cert(domain, "foo", "bar", "baz", "qux")

        self._mock_postfix_and_call(deploy_cert, "example.org")
        # No calls to postconf are expected so mock isn't needed
        deploy_cert("mail.example.org")

    def test_enhance(self):
        self.assertRaises(errors.PluginError,
                          self._create_prepared_installer().enhance,
                          "example.org", "redirect")

    def test_supported_enhancements(self):
        self.assertEqual(
            self._create_prepared_installer().supported_enhancements(), [])

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

        with mock.patch("certbot_postfix.installer.postconf.ConfigMain", return_value=self.mock_postconf):
            with mock.patch("certbot_postfix.installer.util.PostfixUtil", return_value=self.mock_postfix):
                return func(*args, **kwargs)

# TODO (sydli): Remove this object!

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
    def __init__(self, config_dir, initial_values):
        """Create Postfix configuration.

        :param str config_dir: path for Postfix config dir
        :param dict initial_values: initial Postfix config values

        """
        initial_values["config_directory"] = config_dir

        self.config_path = os.path.join(config_dir, "main.cf")
        self._write_config(initial_values)

    def __call__(self, args, *unused_args, **unused_kwargs):
        cmd = os.path.basename(args[0])
        if cmd == "postfix":
            return
        elif cmd != "postconf":  # pragma: no cover
            assert False, "Unexpected command '{0}'".format(''.join(args))

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
                self.set_value(name, value)
            else:
                output.append("{0} = {1}\n".format(arg, self.get_value(arg)))

        return "\n".join(output)

    def get_value(self, name):
        """Returns the value for the Postfix config parameter name.

        If the value isn't set, an empty string is returned.

        :param str name: name of the Postfix config parameter

        :returns: value of the named parameter
        :rtype: str

        """
        return self._read_config().get(name, "")

    def set_value(self, name, value):
        """Sets the value for a Postfix config parameter.

        :param str name: name of the Postfix config parameter
        :param str value: value ot set the parameter to

        """
        config = self._read_config()
        config[name] = value
        self._write_config(config)

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

class MockPostfix(object):
    """Mock utility for Postfix command-line wrapper.
    """
    def __init__(self):
        pass
    def test(self):
        pass
    def restart(self):
        pass
        

class MockPostconf(object):
    """Mock utility for Postconf command-line wrapper.
    """
    def __init__(self, tempdir, init_keys={}):
        self._db = init_keys
        self._db['config_directory'] = tempdir
    def get(self, name):
        if name not in self._db: return None
        return self._db[name]
    def get_default(self, name):
        if name in self._db:
            return self._db[name]
        if name == "mail_version":
            return "3.2.3"
        return None
    def set(self, name, value):
        self._db[name] = value
    def flush(self):
        pass

if __name__ == '__main__':
    unittest.main()  # pragma: no cover
