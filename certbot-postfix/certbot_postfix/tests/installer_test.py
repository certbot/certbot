"""Tests for certbot_postfix.installer."""
import copy
import functools
import os
import unittest
from contextlib import contextmanager

import mock
import pkg_resources
import six
from acme.magic_typing import Dict, Tuple  # pylint: disable=unused-import, no-name-in-module

from certbot import errors
from certbot.tests import util as certbot_test_util


DEFAULT_MAIN_CF = {
    "smtpd_tls_cert_file": "",
    "smtpd_tls_key_file": "",
    "smtpd_tls_dh1024_param_file": "",
    "smtpd_tls_security_level": "none",
    "smtpd_tls_auth_only": "",
    "smtpd_tls_mandatory_protocols": "",
    "smtpd_tls_protocols": "",
    "smtpd_tls_ciphers": "",
    "smtpd_tls_exclude_ciphers": "",
    "smtpd_tls_mandatory_ciphers": "",
    "smtpd_tls_eecdh_grade": "medium",
    "smtp_tls_security_level": "",
    "smtp_tls_ciphers": "",
    "smtp_tls_exclude_ciphers": "",
    "smtp_tls_mandatory_ciphers": "",
    "mail_version": "3.2.3"
}

def _main_cf_with(obj):
    main_cf = copy.copy(DEFAULT_MAIN_CF)
    main_cf.update(obj)
    return main_cf

class InstallerTest(certbot_test_util.ConfigTestCase):
    # pylint: disable=too-many-public-methods

    def setUp(self):
        super(InstallerTest, self).setUp()
        _config_file = pkg_resources.resource_filename("certbot_postfix.tests",
                           os.path.join("testdata", "config.json"))
        self.config.postfix_ctl = "postfix"
        self.config.postfix_config_dir = self.tempdir
        self.config.postfix_config_utility = "postconf"
        self.config.postfix_tls_only = False
        self.config.postfix_server_only = False
        self.config.config_dir = self.tempdir

    @mock.patch("certbot_postfix.installer.util.is_acceptable_value")
    def test_set_vars(self, mock_is_acceptable_value):
        mock_is_acceptable_value.return_value = True
        with create_installer(self.config) as installer:
            installer.prepare()
            mock_is_acceptable_value.return_value = False

    @mock.patch("certbot_postfix.installer.util.is_acceptable_value")
    def test_acceptable_value(self, mock_is_acceptable_value):
        mock_is_acceptable_value.return_value = True
        with create_installer(self.config) as installer:
            installer.prepare()
            mock_is_acceptable_value.return_value = False

    @certbot_test_util.patch_get_utility()
    def test_confirm_changes_no_raises_error(self, mock_util):
        mock_util().yesno.return_value = False
        with create_installer(self.config) as installer:
            installer.prepare()
            self.assertRaises(errors.PluginError, installer.deploy_cert,
                              "example.com", "cert_path", "key_path",
                              "chain_path", "fullchain_path")

    @certbot_test_util.patch_get_utility()
    def test_save(self, mock_util):
        mock_util().yesno.return_value = True
        with create_installer(self.config) as installer:
            installer.prepare()
            installer.postconf.flush = mock.Mock()
            installer.reverter = mock.Mock()
            installer.deploy_cert("example.com", "cert_path", "key_path",
                                  "chain_path", "fullchain_path")
            installer.save()
            self.assertEqual(installer.save_notes, [])
            self.assertEqual(installer.postconf.flush.call_count, 1)
            self.assertEqual(installer.reverter.add_to_checkpoint.call_count, 1)

    @certbot_test_util.patch_get_utility()
    def test_save_with_title(self, mock_util):
        mock_util().yesno.return_value = True
        with create_installer(self.config) as installer:
            installer.prepare()
            installer.postconf.flush = mock.Mock()
            installer.reverter = mock.Mock()
            installer.deploy_cert("example.com", "cert_path", "key_path",
                                  "chain_path", "fullchain_path")
            installer.save(title="new_file!")
            self.assertEqual(installer.reverter.finalize_checkpoint.call_count, 1)

    @certbot_test_util.patch_get_utility()
    def test_rollback_checkpoints_resets_postconf(self, mock_util):
        mock_util().yesno.return_value = True
        with create_installer(self.config) as installer:
            installer.prepare()
            installer.deploy_cert("example.com", "cert_path", "key_path",
                                  "chain_path", "fullchain_path")
            installer.rollback_checkpoints()
            self.assertEqual(installer.postconf.get_changes(), {})

    @certbot_test_util.patch_get_utility()
    def test_recovery_routine_resets_postconf(self, mock_util):
        mock_util().yesno.return_value = True
        with create_installer(self.config) as installer:
            installer.prepare()
            installer.deploy_cert("example.com", "cert_path", "key_path",
                                  "chain_path", "fullchain_path")
            installer.recovery_routine()
            self.assertEqual(installer.postconf.get_changes(), {})

    def test_restart(self):
        with create_installer(self.config) as installer:
            installer.prepare()
            installer.restart()
            self.assertEqual(installer.postfix.restart.call_count, 1)  # pylint: disable=no-member

    def test_add_parser_arguments(self):
        options = set(("ctl", "config-dir", "config-utility",
                       "tls-only", "server-only", "ignore-master-overrides"))
        mock_add = mock.MagicMock()

        from certbot_postfix import installer
        installer.Installer.add_parser_arguments(mock_add)

        for call in mock_add.call_args_list:
            self.assertTrue(call[0][0] in options)

    def test_no_postconf_prepare(self):
        with create_installer(self.config) as installer:
            installer_path = "certbot_postfix.installer"
            exe_exists_path = installer_path + ".certbot_util.exe_exists"
            path_surgery_path = "certbot_postfix.util.plugins_util.path_surgery"
            with mock.patch(path_surgery_path, return_value=False):
                with mock.patch(exe_exists_path, return_value=False):
                    self.assertRaises(errors.NoInstallationError,
                                      installer.prepare)

    def test_old_version(self):
        with create_installer(self.config, main_cf=_main_cf_with({"mail_version": "0.0.1"}))\
                as installer:
            self.assertRaises(errors.NotSupportedError, installer.prepare)

    def test_lock_error(self):
        with create_installer(self.config) as installer:
            assert_raises = functools.partial(self.assertRaises,
                                              errors.PluginError,
                                              installer.prepare)
            certbot_test_util.lock_and_call(assert_raises, self.tempdir)


    @mock.patch('certbot.util.lock_dir_until_exit')
    def test_dir_locked(self, lock_dir):
        with create_installer(self.config) as installer:
            lock_dir.side_effect = errors.LockError
            self.assertRaises(errors.PluginError, installer.prepare)

    def test_more_info(self):
        with create_installer(self.config) as installer:
            installer.prepare()
            output = installer.more_info()
            self.assertTrue("Postfix" in output)
            self.assertTrue(self.tempdir in output)
            self.assertTrue(DEFAULT_MAIN_CF["mail_version"] in output)

    def test_get_all_names(self):
        config = {"mydomain": "example.org",
                  "myhostname": "mail.example.org",
                  "myorigin": "example.org"}
        with create_installer(self.config, main_cf=_main_cf_with(config)) as installer:
            installer.prepare()
            result = installer.get_all_names()
            self.assertEqual(result, set(config.values()))

    @certbot_test_util.patch_get_utility()
    def test_deploy(self, mock_util):
        mock_util().yesno.return_value = True
        from certbot_postfix import constants
        with create_installer(self.config) as installer:
            installer.prepare()

            # pylint: disable=protected-access
            installer.deploy_cert("example.com", "cert_path", "key_path",
                                  "chain_path", "fullchain_path")
            changes = installer.postconf.get_changes()
            expected = {} # type: Dict[str, Tuple[str, ...]]
            expected.update(constants.TLS_SERVER_VARS)
            expected.update(constants.DEFAULT_SERVER_VARS)
            expected.update(constants.DEFAULT_CLIENT_VARS)
            self.assertEqual(changes["smtpd_tls_key_file"], "key_path")
            self.assertEqual(changes["smtpd_tls_cert_file"], "cert_path")
            for name, value in six.iteritems(expected):
                self.assertEqual(changes[name], value[0])

    @certbot_test_util.patch_get_utility()
    def test_tls_only(self, mock_util):
        mock_util().yesno.return_value = True
        with create_installer(self.config) as installer:
            installer.prepare()
            installer.conf = lambda x: x == "tls_only"
            installer.postconf.set = mock.Mock()
            installer.deploy_cert("example.com", "cert_path", "key_path",
                                  "chain_path", "fullchain_path")
            self.assertEqual(installer.postconf.set.call_count, 4)

    @certbot_test_util.patch_get_utility()
    def test_server_only(self, mock_util):
        mock_util().yesno.return_value = True
        with create_installer(self.config) as installer:
            installer.prepare()
            installer.conf = lambda x: x == "server_only"
            installer.postconf.set = mock.Mock()
            installer.deploy_cert("example.com", "cert_path", "key_path",
                                  "chain_path", "fullchain_path")
            self.assertEqual(installer.postconf.set.call_count, 11)

    @certbot_test_util.patch_get_utility()
    def test_tls_and_server_only(self, mock_util):
        mock_util().yesno.return_value = True
        with create_installer(self.config) as installer:
            installer.prepare()
            installer.conf = lambda x: True
            installer.postconf.set = mock.Mock()
            installer.deploy_cert("example.com", "cert_path", "key_path",
                                  "chain_path", "fullchain_path")
            self.assertEqual(installer.postconf.set.call_count, 3)

    @certbot_test_util.patch_get_utility()
    def test_deploy_twice(self, mock_util):
        # Deploying twice on the same installer shouldn't do anything!
        mock_util().yesno.return_value = True
        with create_installer(self.config) as installer:
            installer.prepare()
            from certbot_postfix.postconf import ConfigMain
            with mock.patch.object(ConfigMain, "set", wraps=installer.postconf.set) as fake_set:
                installer.deploy_cert("example.com", "cert_path", "key_path",
                                      "chain_path", "fullchain_path")
                self.assertEqual(fake_set.call_count, 15)
                fake_set.reset_mock()
                installer.deploy_cert("example.com", "cert_path", "key_path",
                                      "chain_path", "fullchain_path")
                self.assertFalse(fake_set.called)

    @certbot_test_util.patch_get_utility()
    def test_deploy_already_secure(self, mock_util):
        # Should not overwrite "more-secure" parameters
        mock_util().yesno.return_value = True
        more_secure = {
            "smtpd_tls_security_level": "encrypt",
            "smtpd_tls_protocols": "!SSLv3, !SSLv2, !TLSv1",
            "smtpd_tls_eecdh_grade": "strong"
        }
        with create_installer(self.config,\
            main_cf=_main_cf_with(more_secure)) as installer:
            installer.prepare()
            installer.deploy_cert("example.com", "cert_path", "key_path",
                                  "chain_path", "fullchain_path")
            for param in more_secure:
                self.assertFalse(param in installer.postconf.get_changes())

    def test_enhance(self):
        with create_installer(self.config) as installer:
            installer.prepare()
            self.assertRaises(errors.PluginError,
                              installer.enhance,
                              "example.org", "redirect")

    def test_supported_enhancements(self):
        with create_installer(self.config) as installer:
            installer.prepare()
            self.assertEqual(installer.supported_enhancements(), [])


@contextmanager
def create_installer(config, main_cf=None):
    """Creates a Postfix installer with calls to `postconf` and `postfix` mocked out.

    In particular, creates a ConfigMain object that does regular things, but seeds it
    with values from `main_cf` and `master_cf` dicts.
    """
    if main_cf is None:
        main_cf = DEFAULT_MAIN_CF

    from certbot_postfix.postconf import ConfigMain
    from certbot_postfix import installer

    def _mock_init_postconf(postconf, executable, ignore_master_overrides=False, config_dir=None):
        # pylint: disable=protected-access,unused-argument
        postconf._ignore_master_overrides = ignore_master_overrides
        postconf._db = main_cf
        postconf._master_db = {}
        postconf._updated = {}
        # override get_default to get from main
        postconf.get_default = lambda name: main_cf[name]
    with mock.patch.object(ConfigMain, "__init__", _mock_init_postconf):
        exe_exists_path = "certbot_postfix.installer.certbot_util.exe_exists"
        with mock.patch(exe_exists_path, return_value=True):
            with mock.patch("certbot_postfix.installer.util.PostfixUtil",
                             return_value=mock.Mock()):
                yield installer.Installer(config, "postfix")


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
