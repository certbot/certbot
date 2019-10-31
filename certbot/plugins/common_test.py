"""Tests for certbot.plugins.common."""
import functools
import shutil
import tempfile
import unittest
import warnings

import OpenSSL
import josepy as jose
import mock

from acme import challenges

from certbot import achallenges
from certbot import crypto_util
from certbot import errors
from certbot.compat import os
from certbot.compat import filesystem
from certbot.tests import acme_util
from certbot.tests import util as test_util

AUTH_KEY = jose.JWKRSA.load(test_util.load_vector("rsa512_key.pem"))
ACHALLS = [
    achallenges.KeyAuthorizationAnnotatedChallenge(
        challb=acme_util.chall_to_challb(
            challenges.TLSSNI01(token=b'token1'), "pending"),
        domain="encryption-example.demo", account_key=AUTH_KEY),
    achallenges.KeyAuthorizationAnnotatedChallenge(
        challb=acme_util.chall_to_challb(
            challenges.TLSSNI01(token=b'token2'), "pending"),
        domain="certbot.demo", account_key=AUTH_KEY),
]

class NamespaceFunctionsTest(unittest.TestCase):
    """Tests for certbot.plugins.common.*_namespace functions."""

    def test_option_namespace(self):
        from certbot.plugins.common import option_namespace
        self.assertEqual("foo-", option_namespace("foo"))

    def test_dest_namespace(self):
        from certbot.plugins.common import dest_namespace
        self.assertEqual("foo_", dest_namespace("foo"))

    def test_dest_namespace_with_dashes(self):
        from certbot.plugins.common import dest_namespace
        self.assertEqual("foo_bar_", dest_namespace("foo-bar"))


class PluginTest(unittest.TestCase):
    """Test for certbot.plugins.common.Plugin."""

    def setUp(self):
        from certbot.plugins.common import Plugin

        class MockPlugin(Plugin):  # pylint: disable=missing-docstring
            @classmethod
            def add_parser_arguments(cls, add):
                add("foo-bar", dest="different_to_foo_bar", x=1, y=None)

        self.plugin_cls = MockPlugin
        self.config = mock.MagicMock()
        self.plugin = MockPlugin(config=self.config, name="mock")

    def test_init(self):
        self.assertEqual("mock", self.plugin.name)
        self.assertEqual(self.config, self.plugin.config)

    def test_option_namespace(self):
        self.assertEqual("mock-", self.plugin.option_namespace)

    def test_option_name(self):
        self.assertEqual("mock-foo_bar", self.plugin.option_name("foo_bar"))

    def test_dest_namespace(self):
        self.assertEqual("mock_", self.plugin.dest_namespace)

    def test_dest(self):
        self.assertEqual("mock_foo_bar", self.plugin.dest("foo-bar"))
        self.assertEqual("mock_foo_bar", self.plugin.dest("foo_bar"))

    def test_conf(self):
        self.assertEqual(self.config.mock_foo_bar, self.plugin.conf("foo-bar"))

    def test_inject_parser_options(self):
        parser = mock.MagicMock()
        self.plugin_cls.inject_parser_options(parser, "mock")
        # note that inject_parser_options doesn't check if dest has
        # correct prefix
        parser.add_argument.assert_called_once_with(
            "--mock-foo-bar", dest="different_to_foo_bar", x=1, y=None)


class InstallerTest(test_util.ConfigTestCase):
    """Tests for certbot.plugins.common.Installer."""

    def setUp(self):
        super(InstallerTest, self).setUp()
        filesystem.mkdir(self.config.config_dir)
        from certbot.plugins.common import Installer

        self.installer = Installer(config=self.config,
                                   name="Installer")
        self.reverter = self.installer.reverter

    def test_add_to_real_checkpoint(self):
        files = set(("foo.bar", "baz.qux",))
        save_notes = "foo bar baz qux"
        self._test_wrapped_method("add_to_checkpoint", files, save_notes)

    def test_add_to_real_checkpoint2(self):
        self._test_add_to_checkpoint_common(False)

    def test_add_to_temporary_checkpoint(self):
        self._test_add_to_checkpoint_common(True)

    def _test_add_to_checkpoint_common(self, temporary):
        files = set(("foo.bar", "baz.qux",))
        save_notes = "foo bar baz qux"

        installer_func = functools.partial(self.installer.add_to_checkpoint,
                                           temporary=temporary)

        if temporary:
            reverter_func_name = "add_to_temp_checkpoint"
        else:
            reverter_func_name = "add_to_checkpoint"

        self._test_adapted_method(installer_func, reverter_func_name, files, save_notes)

    def test_finalize_checkpoint(self):
        self._test_wrapped_method("finalize_checkpoint", "foo")

    def test_recovery_routine(self):
        self._test_wrapped_method("recovery_routine")

    def test_revert_temporary_config(self):
        self._test_wrapped_method("revert_temporary_config")

    def test_rollback_checkpoints(self):
        self._test_wrapped_method("rollback_checkpoints", 42)

    def test_view_config_changes(self):
        self._test_wrapped_method("view_config_changes")

    def test_view_config_changes_warning_supression(self):
        with warnings.catch_warnings():
            # Without the catch_warnings() code in
            # common.Installer.view_config_changes, this would raise an
            # exception. The module parameter here is ".*common$" because the
            # stacklevel=2 parameter of warnings.warn causes the warning to
            # refer to the code in the caller rather than the call to
            # warnings.warn. This means the warning in common.Installer refers
            # to this module and the warning in the reverter refers to the
            # plugins.common module.
            warnings.filterwarnings("error", ".*view_config_changes", module=".*common$")
            self.installer.view_config_changes()

    def _test_wrapped_method(self, name, *args, **kwargs):
        """Test a wrapped reverter method.

        :param str name: name of the method to test
        :param tuple args: position arguments to method
        :param dict kwargs: keyword arguments to method

        """
        installer_func = getattr(self.installer, name)
        self._test_adapted_method(installer_func, name, *args, **kwargs)

    def _test_adapted_method(self, installer_func,
                             reverter_func_name, *passed_args, **passed_kwargs):
        """Test an adapted reverter method

        :param callable installer_func: installer method to test
        :param str reverter_func_name: name of the method on the
            reverter that should be called
        :param tuple passed_args: positional arguments passed from
            installer method to the reverter method
        :param dict passed_kargs: keyword arguments passed from
            installer method to the reverter method

        """
        with mock.patch.object(self.reverter, reverter_func_name) as reverter_func:
            installer_func(*passed_args, **passed_kwargs)
            reverter_func.assert_called_once_with(*passed_args, **passed_kwargs)
            reverter_func.side_effect = errors.ReverterError
            self.assertRaises(
                errors.PluginError, installer_func, *passed_args, **passed_kwargs)

    def test_install_ssl_dhparams(self):
        self.installer.install_ssl_dhparams()
        self.assertTrue(os.path.isfile(self.installer.ssl_dhparams))

    def _current_ssl_dhparams_hash(self):
        from certbot.constants import SSL_DHPARAMS_SRC
        return crypto_util.sha256sum(SSL_DHPARAMS_SRC)

    def test_current_file_hash_in_all_hashes(self):
        from certbot.constants import ALL_SSL_DHPARAMS_HASHES
        self.assertTrue(self._current_ssl_dhparams_hash() in ALL_SSL_DHPARAMS_HASHES,
            "Constants.ALL_SSL_DHPARAMS_HASHES must be appended"
            " with the sha256 hash of self.config.ssl_dhparams when it is updated.")


class AddrTest(unittest.TestCase):
    """Tests for certbot.client.plugins.common.Addr."""

    def setUp(self):
        from certbot.plugins.common import Addr
        self.addr1 = Addr.fromstring("192.168.1.1")
        self.addr2 = Addr.fromstring("192.168.1.1:*")
        self.addr3 = Addr.fromstring("192.168.1.1:80")
        self.addr4 = Addr.fromstring("[fe00::1]")
        self.addr5 = Addr.fromstring("[fe00::1]:*")
        self.addr6 = Addr.fromstring("[fe00::1]:80")
        self.addr7 = Addr.fromstring("[fe00::1]:5")
        self.addr8 = Addr.fromstring("[fe00:1:2:3:4:5:6:7:8:9]:8080")

    def test_fromstring(self):
        self.assertEqual(self.addr1.get_addr(), "192.168.1.1")
        self.assertEqual(self.addr1.get_port(), "")
        self.assertEqual(self.addr2.get_addr(), "192.168.1.1")
        self.assertEqual(self.addr2.get_port(), "*")
        self.assertEqual(self.addr3.get_addr(), "192.168.1.1")
        self.assertEqual(self.addr3.get_port(), "80")
        self.assertEqual(self.addr4.get_addr(), "[fe00::1]")
        self.assertEqual(self.addr4.get_port(), "")
        self.assertEqual(self.addr5.get_addr(), "[fe00::1]")
        self.assertEqual(self.addr5.get_port(), "*")
        self.assertEqual(self.addr6.get_addr(), "[fe00::1]")
        self.assertEqual(self.addr6.get_port(), "80")
        self.assertEqual(self.addr6.get_ipv6_exploded(),
                         "fe00:0:0:0:0:0:0:1")
        self.assertEqual(self.addr1.get_ipv6_exploded(),
                         "")
        self.assertEqual(self.addr7.get_port(), "5")
        self.assertEqual(self.addr8.get_ipv6_exploded(),
                         "fe00:1:2:3:4:5:6:7")

    def test_str(self):
        self.assertEqual(str(self.addr1), "192.168.1.1")
        self.assertEqual(str(self.addr2), "192.168.1.1:*")
        self.assertEqual(str(self.addr3), "192.168.1.1:80")
        self.assertEqual(str(self.addr4), "[fe00::1]")
        self.assertEqual(str(self.addr5), "[fe00::1]:*")
        self.assertEqual(str(self.addr6), "[fe00::1]:80")

    def test_get_addr_obj(self):
        self.assertEqual(str(self.addr1.get_addr_obj("443")), "192.168.1.1:443")
        self.assertEqual(str(self.addr2.get_addr_obj("")), "192.168.1.1")
        self.assertEqual(str(self.addr1.get_addr_obj("*")), "192.168.1.1:*")
        self.assertEqual(str(self.addr4.get_addr_obj("443")), "[fe00::1]:443")
        self.assertEqual(str(self.addr5.get_addr_obj("")), "[fe00::1]")
        self.assertEqual(str(self.addr4.get_addr_obj("*")), "[fe00::1]:*")

    def test_eq(self):
        self.assertEqual(self.addr1, self.addr2.get_addr_obj(""))
        self.assertNotEqual(self.addr1, self.addr2)
        self.assertFalse(self.addr1 == 3333)

        self.assertEqual(self.addr4, self.addr4.get_addr_obj(""))
        self.assertNotEqual(self.addr4, self.addr5)
        self.assertFalse(self.addr4 == 3333)
        from certbot.plugins.common import Addr
        self.assertEqual(self.addr4, Addr.fromstring("[fe00:0:0::1]"))
        self.assertEqual(self.addr4, Addr.fromstring("[fe00:0::0:0:1]"))


    def test_set_inclusion(self):
        from certbot.plugins.common import Addr
        set_a = set([self.addr1, self.addr2])
        addr1b = Addr.fromstring("192.168.1.1")
        addr2b = Addr.fromstring("192.168.1.1:*")
        set_b = set([addr1b, addr2b])

        self.assertEqual(set_a, set_b)

        set_c = set([self.addr4, self.addr5])
        addr4b = Addr.fromstring("[fe00::1]")
        addr5b = Addr.fromstring("[fe00::1]:*")
        set_d = set([addr4b, addr5b])

        self.assertEqual(set_c, set_d)


class ChallengePerformerTest(unittest.TestCase):
    """Tests for certbot.plugins.common.ChallengePerformer."""

    def setUp(self):
        configurator = mock.MagicMock()

        from certbot.plugins.common import ChallengePerformer
        self.performer = ChallengePerformer(configurator)

    def test_add_chall(self):
        self.performer.add_chall(ACHALLS[0], 0)
        self.assertEqual(1, len(self.performer.achalls))
        self.assertEqual([0], self.performer.indices)

    def test_perform(self):
        self.assertRaises(NotImplementedError, self.performer.perform)


class TLSSNI01Test(unittest.TestCase):
    """Tests for certbot.plugins.common.TLSSNI01."""

    def setUp(self):
        self.tempdir = tempfile.mkdtemp()
        configurator = mock.MagicMock()
        configurator.config.config_dir = os.path.join(self.tempdir, "config")
        configurator.config.work_dir = os.path.join(self.tempdir, "work")

        from certbot.plugins.common import TLSSNI01
        self.sni = TLSSNI01(configurator=configurator)

    def tearDown(self):
        shutil.rmtree(self.tempdir)

    def test_setup_challenge_cert(self):
        # This is a helper function that can be used for handling
        # open context managers more elegantly. It avoids dealing with
        # __enter__ and __exit__ calls.
        # http://www.voidspace.org.uk/python/mock/helpers.html#mock.mock_open
        mock_open, mock_safe_open = mock.mock_open(), mock.mock_open()

        response = challenges.TLSSNI01Response()
        achall = mock.MagicMock()
        achall.chall.encode.return_value = "token"
        key = test_util.load_pyopenssl_private_key("rsa512_key.pem")
        achall.response_and_validation.return_value = (
            response, (test_util.load_cert("cert_512.pem"), key))

        with mock.patch("certbot.plugins.common.open",
                        mock_open, create=True):
            with mock.patch("certbot.plugins.common.util.safe_open",
                            mock_safe_open):
                # pylint: disable=protected-access
                self.assertEqual(response, self.sni._setup_challenge_cert(
                    achall, "randomS1"))

        # pylint: disable=no-member
        mock_open.assert_called_once_with(self.sni.get_cert_path(achall), "wb")
        mock_open.return_value.write.assert_called_once_with(
            test_util.load_vector("cert_512.pem"))
        mock_safe_open.assert_called_once_with(
            self.sni.get_key_path(achall), "wb", chmod=0o400)
        mock_safe_open.return_value.write.assert_called_once_with(
            OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, key))

    def test_get_z_domain(self):
        achall = ACHALLS[0]
        self.assertEqual(self.sni.get_z_domain(achall),
            achall.response(achall.account_key).z_domain.decode("utf-8"))

    def test_warning(self):
        with mock.patch('certbot.plugins.common.warnings.warn') as mock_warn:
            from certbot.plugins.common import TLSSNI01  # pylint: disable=unused-variable
        self.assertTrue(mock_warn.call_args[0][0].startswith('TLSSNI01'))


class InstallVersionControlledFileTest(test_util.TempDirTestCase):
    """Tests for certbot.plugins.common.install_version_controlled_file."""

    def setUp(self):
        super(InstallVersionControlledFileTest, self).setUp()
        self.hashes = ["someotherhash"]
        self.dest_path = os.path.join(self.tempdir, "options-ssl-dest.conf")
        self.hash_path = os.path.join(self.tempdir, ".options-ssl-conf.txt")
        self.old_path = os.path.join(self.tempdir, "options-ssl-old.conf")
        self.source_path = os.path.join(self.tempdir, "options-ssl-src.conf")
        for path in (self.source_path, self.old_path,):
            with open(path, "w") as f:
                f.write(path)
            self.hashes.append(crypto_util.sha256sum(path))

    def _call(self):
        from certbot.plugins.common import install_version_controlled_file
        install_version_controlled_file(self.dest_path,
                                        self.hash_path,
                                        self.source_path,
                                        self.hashes)

    def _current_file_hash(self):
        return crypto_util.sha256sum(self.source_path)

    def _assert_current_file(self):
        self.assertTrue(os.path.isfile(self.dest_path))
        self.assertEqual(crypto_util.sha256sum(self.dest_path),
            self._current_file_hash())

    def test_no_file(self):
        self.assertFalse(os.path.isfile(self.dest_path))
        self._call()
        self._assert_current_file()

    def test_current_file(self):
        # 1st iteration installs the file, the 2nd checks if it needs updating
        for _ in range(2):
            self._call()
            self._assert_current_file()

    def test_prev_file_updates_to_current(self):
        shutil.copyfile(self.old_path, self.dest_path)
        self._call()
        self._assert_current_file()

    def test_manually_modified_current_file_does_not_update(self):
        self._call()
        with open(self.dest_path, "a") as mod_ssl_conf:
            mod_ssl_conf.write("a new line for the wrong hash\n")
        with mock.patch("certbot.plugins.common.logger") as mock_logger:
            self._call()
            self.assertFalse(mock_logger.warning.called)
        self.assertTrue(os.path.isfile(self.dest_path))
        self.assertEqual(crypto_util.sha256sum(self.source_path),
            self._current_file_hash())
        self.assertNotEqual(crypto_util.sha256sum(self.dest_path),
            self._current_file_hash())

    def test_manually_modified_past_file_warns(self):
        with open(self.dest_path, "a") as mod_ssl_conf:
            mod_ssl_conf.write("a new line for the wrong hash\n")
        with open(self.hash_path, "w") as f:
            f.write("hashofanoldversion")
        with mock.patch("certbot.plugins.common.logger") as mock_logger:
            self._call()
            self.assertEqual(mock_logger.warning.call_args[0][0],
                "%s has been manually modified; updated file "
                "saved to %s. We recommend updating %s for security purposes.")
        self.assertEqual(crypto_util.sha256sum(self.source_path),
            self._current_file_hash())
        # only print warning once
        with mock.patch("certbot.plugins.common.logger") as mock_logger:
            self._call()
            self.assertFalse(mock_logger.warning.called)

if __name__ == "__main__":
    unittest.main()  # pragma: no cover
