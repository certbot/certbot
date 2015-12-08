# pylint: disable=too-many-public-methods
"""Test for letsencrypt_apache.configurator."""
import os
import shutil
import socket
import unittest

import mock

from acme import challenges

from letsencrypt import achallenges
from letsencrypt import errors

from letsencrypt.tests import acme_util

from letsencrypt_apache import configurator
from letsencrypt_apache import obj

from letsencrypt_apache.tests import util


class TwoVhost80Test(util.ApacheTest):
    """Test two standard well-configured HTTP vhosts."""

    def setUp(self):  # pylint: disable=arguments-differ
        super(TwoVhost80Test, self).setUp()

        self.config = util.get_apache_configurator(
            self.config_path, self.config_dir, self.work_dir)

        self.vh_truth = util.get_vh_truth(
            self.temp_dir, "debian_apache_2_4/two_vhost_80")

    def tearDown(self):
        shutil.rmtree(self.temp_dir)
        shutil.rmtree(self.config_dir)
        shutil.rmtree(self.work_dir)

    @mock.patch("letsencrypt_apache.configurator.le_util.exe_exists")
    def test_prepare_no_install(self, mock_exe_exists):
        mock_exe_exists.return_value = False
        self.assertRaises(
            errors.NoInstallationError, self.config.prepare)

    @mock.patch("letsencrypt_apache.parser.ApacheParser")
    @mock.patch("letsencrypt_apache.configurator.le_util.exe_exists")
    def test_prepare_version(self, mock_exe_exists, _):
        mock_exe_exists.return_value = True
        self.config.version = None
        self.config.config_test = mock.Mock()
        self.config.get_version = mock.Mock(return_value=(1, 1))

        self.assertRaises(
            errors.NotSupportedError, self.config.prepare)

    def test_add_parser_arguments(self):  # pylint: disable=no-self-use
        from letsencrypt_apache.configurator import ApacheConfigurator
        # Weak test..
        ApacheConfigurator.add_parser_arguments(mock.MagicMock())

    @mock.patch("zope.component.getUtility")
    def test_get_all_names(self, mock_getutility):
        mock_getutility.notification = mock.MagicMock(return_value=True)
        names = self.config.get_all_names()
        self.assertEqual(names, set(
            ["letsencrypt.demo", "encryption-example.demo", "ip-172-30-0-17"]))

    @mock.patch("zope.component.getUtility")
    @mock.patch("letsencrypt_apache.configurator.socket.gethostbyaddr")
    def test_get_all_names_addrs(self, mock_gethost, mock_getutility):
        mock_gethost.side_effect = [("google.com", "", ""), socket.error]
        notification = mock.Mock()
        notification.notification = mock.Mock(return_value=True)
        mock_getutility.return_value = notification
        vhost = obj.VirtualHost(
            "fp", "ap",
            set([obj.Addr(("8.8.8.8", "443")),
                 obj.Addr(("zombo.com",)),
                 obj.Addr(("192.168.1.2"))]),
            True, False)
        self.config.vhosts.append(vhost)

        names = self.config.get_all_names()
        self.assertEqual(len(names), 5)
        self.assertTrue("zombo.com" in names)
        self.assertTrue("google.com" in names)
        self.assertTrue("letsencrypt.demo" in names)

    def test_add_servernames_alias(self):
        self.config.parser.add_dir(
            self.vh_truth[2].path, "ServerAlias", ["*.le.co"])
        self.config._add_servernames(self.vh_truth[2])  # pylint: disable=protected-access

        self.assertEqual(
            self.vh_truth[2].get_names(), set(["*.le.co", "ip-172-30-0-17"]))

    def test_get_virtual_hosts(self):
        """Make sure all vhosts are being properly found.

        .. note:: If test fails, only finding 1 Vhost... it is likely that
            it is a problem with is_enabled.  If finding only 3, likely is_ssl

        """
        vhs = self.config.get_virtual_hosts()
        self.assertEqual(len(vhs), 6)
        found = 0

        for vhost in vhs:
            for truth in self.vh_truth:
                if vhost == truth:
                    found += 1
                    break
            else:
                raise Exception("Missed: %s" % vhost)  # pragma: no cover

        self.assertEqual(found, 6)

    @mock.patch("letsencrypt_apache.display_ops.select_vhost")
    def test_choose_vhost_none_avail(self, mock_select):
        mock_select.return_value = None
        self.assertRaises(
            errors.PluginError, self.config.choose_vhost, "none.com")

    @mock.patch("letsencrypt_apache.display_ops.select_vhost")
    def test_choose_vhost_select_vhost_ssl(self, mock_select):
        mock_select.return_value = self.vh_truth[1]
        self.assertEqual(
            self.vh_truth[1], self.config.choose_vhost("none.com"))

    @mock.patch("letsencrypt_apache.display_ops.select_vhost")
    def test_choose_vhost_select_vhost_non_ssl(self, mock_select):
        mock_select.return_value = self.vh_truth[0]
        chosen_vhost = self.config.choose_vhost("none.com")
        self.assertEqual(
            self.vh_truth[0].get_names(), chosen_vhost.get_names())

        # Make sure we go from HTTP -> HTTPS
        self.assertFalse(self.vh_truth[0].ssl)
        self.assertTrue(chosen_vhost.ssl)

    @mock.patch("letsencrypt_apache.display_ops.select_vhost")
    def test_choose_vhost_select_vhost_with_temp(self, mock_select):
        mock_select.return_value = self.vh_truth[0]
        chosen_vhost = self.config.choose_vhost("none.com", temp=True)
        self.assertEqual(self.vh_truth[0], chosen_vhost)

    @mock.patch("letsencrypt_apache.display_ops.select_vhost")
    def test_choose_vhost_select_vhost_conflicting_non_ssl(self, mock_select):
        mock_select.return_value = self.vh_truth[3]
        conflicting_vhost = obj.VirtualHost(
            "path", "aug_path", set([obj.Addr.fromstring("*:443")]), True, True)
        self.config.vhosts.append(conflicting_vhost)

        self.assertRaises(
            errors.PluginError, self.config.choose_vhost, "none.com")

    def test_find_best_vhost(self):
        # pylint: disable=protected-access
        self.assertEqual(
            self.vh_truth[3], self.config._find_best_vhost("letsencrypt.demo"))
        self.assertEqual(
            self.vh_truth[0],
            self.config._find_best_vhost("encryption-example.demo"))
        self.assertTrue(
            self.config._find_best_vhost("does-not-exist.com") is None)

    def test_find_best_vhost_variety(self):
        # pylint: disable=protected-access
        ssl_vh = obj.VirtualHost(
            "fp", "ap", set([obj.Addr(("*", "443")), obj.Addr(("zombo.com",))]),
            True, False)
        self.config.vhosts.append(ssl_vh)
        self.assertEqual(self.config._find_best_vhost("zombo.com"), ssl_vh)

    def test_find_best_vhost_default(self):
        # pylint: disable=protected-access
        # Assume only the two default vhosts.
        self.config.vhosts = [
            vh for vh in self.config.vhosts
            if vh.name not in ["letsencrypt.demo", "encryption-example.demo"]
        ]

        self.assertEqual(
            self.config._find_best_vhost("example.demo"), self.vh_truth[2])

    def test_non_default_vhosts(self):
        # pylint: disable=protected-access
        self.assertEqual(len(self.config._non_default_vhosts()), 4)

    def test_is_site_enabled(self):
        """Test if site is enabled.

        .. note:: This test currently fails for hard links
            (which may happen if you move dirs incorrectly)
        .. warning:: This test does not work when running using the
            unittest.main() function. It incorrectly copies symlinks.

        """
        self.assertTrue(self.config.is_site_enabled(self.vh_truth[0].filep))
        self.assertFalse(self.config.is_site_enabled(self.vh_truth[1].filep))
        self.assertTrue(self.config.is_site_enabled(self.vh_truth[2].filep))
        self.assertTrue(self.config.is_site_enabled(self.vh_truth[3].filep))

    @mock.patch("letsencrypt.le_util.run_script")
    @mock.patch("letsencrypt.le_util.exe_exists")
    @mock.patch("letsencrypt_apache.parser.subprocess.Popen")
    def test_enable_mod(self, mock_popen, mock_exe_exists, mock_run_script):
        mock_popen().communicate.return_value = ("Define: DUMP_RUN_CFG", "")
        mock_popen().returncode = 0
        mock_exe_exists.return_value = True

        self.config.enable_mod("ssl")
        self.assertTrue("ssl_module" in self.config.parser.modules)
        self.assertTrue("mod_ssl.c" in self.config.parser.modules)

        self.assertTrue(mock_run_script.called)

    def test_enable_mod_unsupported_dirs(self):
        shutil.rmtree(os.path.join(self.config.parser.root, "mods-enabled"))
        self.assertRaises(
            errors.NotSupportedError, self.config.enable_mod, "ssl")

    @mock.patch("letsencrypt.le_util.exe_exists")
    def test_enable_mod_no_disable(self, mock_exe_exists):
        mock_exe_exists.return_value = False
        self.assertRaises(
            errors.MisconfigurationError, self.config.enable_mod, "ssl")

    def test_enable_site(self):
        # Default 443 vhost
        self.assertFalse(self.vh_truth[1].enabled)
        self.config.enable_site(self.vh_truth[1])
        self.assertTrue(self.vh_truth[1].enabled)

        # Go again to make sure nothing fails
        self.config.enable_site(self.vh_truth[1])

    def test_enable_site_failure(self):
        self.assertRaises(
            errors.NotSupportedError,
            self.config.enable_site,
            obj.VirtualHost("asdf", "afsaf", set(), False, False))

    def test_deploy_cert_newssl(self):
        self.config = util.get_apache_configurator(
            self.config_path, self.config_dir, self.work_dir, version=(2, 4, 16))

        self.config.parser.modules.add("ssl_module")
        self.config.parser.modules.add("mod_ssl.c")

        # Get the default 443 vhost
        self.config.assoc["random.demo"] = self.vh_truth[1]
        self.config.deploy_cert(
            "random.demo", "example/cert.pem", "example/key.pem",
            "example/cert_chain.pem", "example/fullchain.pem")
        self.config.save()

        # Verify ssl_module was enabled.
        self.assertTrue(self.vh_truth[1].enabled)
        self.assertTrue("ssl_module" in self.config.parser.modules)

        loc_cert = self.config.parser.find_dir(
            "sslcertificatefile", "example/fullchain.pem", self.vh_truth[1].path)
        loc_key = self.config.parser.find_dir(
            "sslcertificateKeyfile", "example/key.pem", self.vh_truth[1].path)

        # Verify one directive was found in the correct file
        self.assertEqual(len(loc_cert), 1)
        self.assertEqual(configurator.get_file_path(loc_cert[0]),
                         self.vh_truth[1].filep)

        self.assertEqual(len(loc_key), 1)
        self.assertEqual(configurator.get_file_path(loc_key[0]),
                         self.vh_truth[1].filep)

    def test_deploy_cert_newssl_no_fullchain(self):
        self.config = util.get_apache_configurator(
            self.config_path, self.config_dir, self.work_dir, version=(2, 4, 16))

        self.config.parser.modules.add("ssl_module")
        self.config.parser.modules.add("mod_ssl.c")

        # Get the default 443 vhost
        self.config.assoc["random.demo"] = self.vh_truth[1]
        self.assertRaises(errors.PluginError,
                          lambda: self.config.deploy_cert(
                              "random.demo", "example/cert.pem", "example/key.pem"))

    def test_deploy_cert_old_apache_no_chain(self):
        self.config = util.get_apache_configurator(
            self.config_path, self.config_dir, self.work_dir, version=(2, 4, 7))

        self.config.parser.modules.add("ssl_module")
        self.config.parser.modules.add("mod_ssl.c")

        # Get the default 443 vhost
        self.config.assoc["random.demo"] = self.vh_truth[1]
        self.assertRaises(errors.PluginError,
                          lambda: self.config.deploy_cert(
                              "random.demo", "example/cert.pem", "example/key.pem"))

    def test_deploy_cert(self):
        self.config.parser.modules.add("ssl_module")
        self.config.parser.modules.add("mod_ssl.c")

        # Get the default 443 vhost
        self.config.assoc["random.demo"] = self.vh_truth[1]
        self.config.deploy_cert(
            "random.demo",
            "example/cert.pem", "example/key.pem", "example/cert_chain.pem")
        self.config.save()

        # Verify ssl_module was enabled.
        self.assertTrue(self.vh_truth[1].enabled)
        self.assertTrue("ssl_module" in self.config.parser.modules)

        loc_cert = self.config.parser.find_dir(
            "sslcertificatefile", "example/cert.pem", self.vh_truth[1].path)
        loc_key = self.config.parser.find_dir(
            "sslcertificateKeyfile", "example/key.pem", self.vh_truth[1].path)
        loc_chain = self.config.parser.find_dir(
            "SSLCertificateChainFile", "example/cert_chain.pem",
            self.vh_truth[1].path)

        # Verify one directive was found in the correct file
        self.assertEqual(len(loc_cert), 1)
        self.assertEqual(configurator.get_file_path(loc_cert[0]),
                         self.vh_truth[1].filep)

        self.assertEqual(len(loc_key), 1)
        self.assertEqual(configurator.get_file_path(loc_key[0]),
                         self.vh_truth[1].filep)

        self.assertEqual(len(loc_chain), 1)
        self.assertEqual(configurator.get_file_path(loc_chain[0]),
                         self.vh_truth[1].filep)

        # One more time for chain directive setting
        self.config.deploy_cert(
            "random.demo",
            "two/cert.pem", "two/key.pem", "two/cert_chain.pem")
        self.assertTrue(self.config.parser.find_dir(
            "SSLCertificateChainFile", "two/cert_chain.pem",
            self.vh_truth[1].path))

    def test_deploy_cert_invalid_vhost(self):
        self.config.parser.modules.add("ssl_module")
        mock_find = mock.MagicMock()
        mock_find.return_value = []
        self.config.parser.find_dir = mock_find

        # Get the default 443 vhost
        self.config.assoc["random.demo"] = self.vh_truth[1]
        self.assertRaises(
            errors.PluginError, self.config.deploy_cert, "random.demo",
            "example/cert.pem", "example/key.pem", "example/cert_chain.pem")

    def test_is_name_vhost(self):
        addr = obj.Addr.fromstring("*:80")
        self.assertTrue(self.config.is_name_vhost(addr))
        self.config.version = (2, 2)
        self.assertFalse(self.config.is_name_vhost(addr))

    def test_add_name_vhost(self):
        self.config.add_name_vhost(obj.Addr.fromstring("*:443"))
        self.config.add_name_vhost(obj.Addr.fromstring("*:80"))
        self.assertTrue(self.config.parser.find_dir(
            "NameVirtualHost", "*:443", exclude=False))
        self.assertTrue(self.config.parser.find_dir(
            "NameVirtualHost", "*:80"))

    def test_prepare_server_https(self):
        mock_enable = mock.Mock()
        self.config.enable_mod = mock_enable

        mock_find = mock.Mock()
        mock_add_dir = mock.Mock()
        mock_find.return_value = []

        # This will test the Add listen
        self.config.parser.find_dir = mock_find
        self.config.parser.add_dir_to_ifmodssl = mock_add_dir

        self.config.prepare_server_https("443")
        self.assertEqual(mock_enable.call_args[1], {"temp": False})

        self.config.prepare_server_https("8080", temp=True)
        # Enable mod is temporary
        self.assertEqual(mock_enable.call_args[1], {"temp": True})

        self.assertEqual(mock_add_dir.call_count, 2)

    def test_make_vhost_ssl(self):
        ssl_vhost = self.config.make_vhost_ssl(self.vh_truth[0])

        self.assertEqual(
            ssl_vhost.filep,
            os.path.join(self.config_path, "sites-available",
                         "encryption-example-le-ssl.conf"))

        self.assertEqual(ssl_vhost.path,
                         "/files" + ssl_vhost.filep + "/IfModule/VirtualHost")
        self.assertEqual(len(ssl_vhost.addrs), 1)
        self.assertEqual(set([obj.Addr.fromstring("*:443")]), ssl_vhost.addrs)
        self.assertEqual(ssl_vhost.name, "encryption-example.demo")
        self.assertTrue(ssl_vhost.ssl)
        self.assertFalse(ssl_vhost.enabled)

        self.assertTrue(self.config.parser.find_dir(
            "SSLCertificateFile", None, ssl_vhost.path, False))
        self.assertTrue(self.config.parser.find_dir(
            "SSLCertificateKeyFile", None, ssl_vhost.path, False))

        self.assertEqual(self.config.is_name_vhost(self.vh_truth[0]),
                         self.config.is_name_vhost(ssl_vhost))

        self.assertEqual(len(self.config.vhosts), 7)

    def test_clean_vhost_ssl(self):
        # pylint: disable=protected-access
        for directive in ["SSLCertificateFile", "SSLCertificateKeyFile",
                          "SSLCertificateChainFile", "SSLCACertificatePath"]:
            for _ in range(10):
                self.config.parser.add_dir(self.vh_truth[1].path, directive, ["bogus"])
        self.config.save()

        self.config._clean_vhost(self.vh_truth[1])
        self.config.save()

        loc_cert = self.config.parser.find_dir(
            'SSLCertificateFile', None, self.vh_truth[1].path, False)
        loc_key = self.config.parser.find_dir(
            'SSLCertificateKeyFile', None, self.vh_truth[1].path, False)
        loc_chain = self.config.parser.find_dir(
            'SSLCertificateChainFile', None, self.vh_truth[1].path, False)
        loc_cacert = self.config.parser.find_dir(
            'SSLCACertificatePath', None, self.vh_truth[1].path, False)

        self.assertEqual(len(loc_cert), 1)
        self.assertEqual(len(loc_key), 1)

        self.assertEqual(len(loc_chain), 0)

        self.assertEqual(len(loc_cacert), 10)

    def test_deduplicate_directives(self):
        # pylint: disable=protected-access
        DIRECTIVE = "Foo"
        for _ in range(10):
            self.config.parser.add_dir(self.vh_truth[1].path, DIRECTIVE, ["bar"])
        self.config.save()

        self.config._deduplicate_directives(self.vh_truth[1].path, [DIRECTIVE])
        self.config.save()

        self.assertEqual(
                         len(self.config.parser.find_dir(
                             DIRECTIVE, None, self.vh_truth[1].path, False)),
                         1)

    def test_remove_directives(self):
        # pylint: disable=protected-access
        DIRECTIVES = ["Foo", "Bar"]
        for directive in DIRECTIVES:
            for _ in range(10):
                self.config.parser.add_dir(self.vh_truth[1].path, directive, ["baz"])
        self.config.save()

        self.config._remove_directives(self.vh_truth[1].path, DIRECTIVES)
        self.config.save()

        for directive in DIRECTIVES:
            self.assertEqual(
                             len(self.config.parser.find_dir(
                                 directive, None, self.vh_truth[1].path, False)),
                             0)

    def test_make_vhost_ssl_extra_vhs(self):
        self.config.aug.match = mock.Mock(return_value=["p1", "p2"])
        self.assertRaises(
            errors.PluginError, self.config.make_vhost_ssl, self.vh_truth[0])

    def test_make_vhost_ssl_bad_write(self):
        mock_open = mock.mock_open()
        # This calls open
        self.config.reverter.register_file_creation = mock.Mock()
        mock_open.side_effect = IOError
        with mock.patch("__builtin__.open", mock_open):
            self.assertRaises(
                errors.PluginError,
                self.config.make_vhost_ssl, self.vh_truth[0])

    def test_get_ssl_vhost_path(self):
        # pylint: disable=protected-access
        self.assertTrue(
            self.config._get_ssl_vhost_path("example_path").endswith(".conf"))

    def test_add_name_vhost_if_necessary(self):
        # pylint: disable=protected-access
        self.config.save = mock.Mock()
        self.config.version = (2, 2)
        self.config._add_name_vhost_if_necessary(self.vh_truth[0])
        self.assertTrue(self.config.save.called)

    @mock.patch("letsencrypt_apache.configurator.tls_sni_01.ApacheTlsSni01.perform")
    @mock.patch("letsencrypt_apache.configurator.ApacheConfigurator.restart")
    def test_perform(self, mock_restart, mock_perform):
        # Only tests functionality specific to configurator.perform
        # Note: As more challenges are offered this will have to be expanded
        account_key, achall1, achall2 = self.get_achalls()

        expected = [
            achall1.response(account_key),
            achall2.response(account_key),
        ]

        mock_perform.return_value = expected
        responses = self.config.perform([achall1, achall2])

        self.assertEqual(mock_perform.call_count, 1)
        self.assertEqual(responses, expected)

        self.assertEqual(mock_restart.call_count, 1)

    @mock.patch("letsencrypt_apache.configurator.ApacheConfigurator.restart")
    def test_cleanup(self, mock_restart):
        _, achall1, achall2 = self.get_achalls()

        self.config._chall_out.add(achall1)  # pylint: disable=protected-access
        self.config._chall_out.add(achall2)  # pylint: disable=protected-access

        self.config.cleanup([achall1])
        self.assertFalse(mock_restart.called)

        self.config.cleanup([achall2])
        self.assertTrue(mock_restart.called)

    @mock.patch("letsencrypt_apache.configurator.ApacheConfigurator.restart")
    def test_cleanup_no_errors(self, mock_restart):
        _, achall1, achall2 = self.get_achalls()

        self.config._chall_out.add(achall1)  # pylint: disable=protected-access

        self.config.cleanup([achall2])
        self.assertFalse(mock_restart.called)

        self.config.cleanup([achall1, achall2])
        self.assertTrue(mock_restart.called)

    @mock.patch("letsencrypt.le_util.run_script")
    def test_get_version(self, mock_script):
        mock_script.return_value = (
            "Server Version: Apache/2.4.2 (Debian)", "")
        self.assertEqual(self.config.get_version(), (2, 4, 2))

        mock_script.return_value = (
            "Server Version: Apache/2 (Linux)", "")
        self.assertEqual(self.config.get_version(), (2,))

        mock_script.return_value = (
            "Server Version: Apache (Debian)", "")
        self.assertRaises(errors.PluginError, self.config.get_version)

        mock_script.return_value = (
            "Server Version: Apache/2.3{0} Apache/2.4.7".format(os.linesep), "")
        self.assertRaises(errors.PluginError, self.config.get_version)

        mock_script.side_effect = errors.SubprocessError("Can't find program")
        self.assertRaises(errors.PluginError, self.config.get_version)

    @mock.patch("letsencrypt_apache.configurator.le_util.run_script")
    def test_restart(self, _):
        self.config.restart()

    @mock.patch("letsencrypt_apache.configurator.le_util.run_script")
    def test_restart_bad_process(self, mock_run_script):
        mock_run_script.side_effect = [None, errors.SubprocessError]

        self.assertRaises(errors.MisconfigurationError, self.config.restart)

    @mock.patch("letsencrypt.le_util.run_script")
    def test_config_test(self, _):
        self.config.config_test()

    @mock.patch("letsencrypt.le_util.run_script")
    def test_config_test_bad_process(self, mock_run_script):
        mock_run_script.side_effect = errors.SubprocessError

        self.assertRaises(errors.MisconfigurationError, self.config.config_test)

    def test_get_all_certs_keys(self):
        c_k = self.config.get_all_certs_keys()

        self.assertEqual(len(c_k), 2)
        cert, key, path = next(iter(c_k))
        self.assertTrue("cert" in cert)
        self.assertTrue("key" in key)
        self.assertTrue("default-ssl" in path)

    def test_get_all_certs_keys_malformed_conf(self):
        self.config.parser.find_dir = mock.Mock(side_effect=[["path"], [], ["path"], []])
        c_k = self.config.get_all_certs_keys()

        self.assertFalse(c_k)

    def test_more_info(self):
        self.assertTrue(self.config.more_info())

    def test_get_chall_pref(self):
        self.assertTrue(isinstance(self.config.get_chall_pref(""), list))

    def test_install_ssl_options_conf(self):
        from letsencrypt_apache.configurator import install_ssl_options_conf
        path = os.path.join(self.work_dir, "test_it")
        install_ssl_options_conf(path)
        self.assertTrue(os.path.isfile(path))

    # TEST ENHANCEMENTS
    def test_supported_enhancements(self):
        self.assertTrue(isinstance(self.config.supported_enhancements(), list))

    def test_enhance_unknown_enhancement(self):
        self.assertRaises(
            errors.PluginError,
            self.config.enhance, "letsencrypt.demo", "unknown_enhancement")

    @mock.patch("letsencrypt.le_util.run_script")
    @mock.patch("letsencrypt.le_util.exe_exists")
    def test_http_header_hsts(self, mock_exe, _):
        self.config.parser.update_runtime_variables = mock.Mock()
        self.config.parser.modules.add("mod_ssl.c")
        mock_exe.return_value = True

        # This will create an ssl vhost for letsencrypt.demo
        self.config.enhance("letsencrypt.demo", "ensure-http-header",
                "Strict-Transport-Security")

        self.assertTrue("headers_module" in self.config.parser.modules)

        # Get the ssl vhost for letsencrypt.demo
        ssl_vhost = self.config.assoc["letsencrypt.demo"]

        # These are not immediately available in find_dir even with save() and
        # load(). They must be found in sites-available
        hsts_header = self.config.parser.find_dir(
                "Header", None, ssl_vhost.path)

        # four args to HSTS header
        self.assertEqual(len(hsts_header), 4)

    def test_http_header_hsts_twice(self):
        self.config.parser.modules.add("mod_ssl.c")
        # skip the enable mod
        self.config.parser.modules.add("headers_module")

        # This will create an ssl vhost for letsencrypt.demo
        self.config.enhance("encryption-example.demo", "ensure-http-header",
                "Strict-Transport-Security")

        self.assertRaises(
            errors.PluginEnhancementAlreadyPresent,
            self.config.enhance, "encryption-example.demo", "ensure-http-header",
            "Strict-Transport-Security")

    @mock.patch("letsencrypt.le_util.run_script")
    @mock.patch("letsencrypt.le_util.exe_exists")
    def test_http_header_uir(self, mock_exe, _):
        self.config.parser.update_runtime_variables = mock.Mock()
        self.config.parser.modules.add("mod_ssl.c")
        mock_exe.return_value = True

        # This will create an ssl vhost for letsencrypt.demo
        self.config.enhance("letsencrypt.demo", "ensure-http-header",
                "Upgrade-Insecure-Requests")

        self.assertTrue("headers_module" in self.config.parser.modules)

        # Get the ssl vhost for letsencrypt.demo
        ssl_vhost = self.config.assoc["letsencrypt.demo"]

        # These are not immediately available in find_dir even with save() and
        # load(). They must be found in sites-available
        uir_header = self.config.parser.find_dir(
                "Header", None, ssl_vhost.path)

        # four args to HSTS header
        self.assertEqual(len(uir_header), 4)

    def test_http_header_uir_twice(self):
        self.config.parser.modules.add("mod_ssl.c")
        # skip the enable mod
        self.config.parser.modules.add("headers_module")

        # This will create an ssl vhost for letsencrypt.demo
        self.config.enhance("encryption-example.demo", "ensure-http-header",
                "Upgrade-Insecure-Requests")

        self.assertRaises(
            errors.PluginEnhancementAlreadyPresent,
            self.config.enhance, "encryption-example.demo", "ensure-http-header",
            "Upgrade-Insecure-Requests")



    @mock.patch("letsencrypt.le_util.run_script")
    @mock.patch("letsencrypt.le_util.exe_exists")
    def test_redirect_well_formed_http(self, mock_exe, _):
        self.config.parser.update_runtime_variables = mock.Mock()
        mock_exe.return_value = True
        # This will create an ssl vhost for letsencrypt.demo
        self.config.enhance("letsencrypt.demo", "redirect")

        # These are not immediately available in find_dir even with save() and
        # load(). They must be found in sites-available
        rw_engine = self.config.parser.find_dir(
            "RewriteEngine", "on", self.vh_truth[3].path)
        rw_rule = self.config.parser.find_dir(
            "RewriteRule", None, self.vh_truth[3].path)

        self.assertEqual(len(rw_engine), 1)
        # three args to rw_rule
        self.assertEqual(len(rw_rule), 3)

        self.assertTrue(rw_engine[0].startswith(self.vh_truth[3].path))
        self.assertTrue(rw_rule[0].startswith(self.vh_truth[3].path))

        self.assertTrue("rewrite_module" in self.config.parser.modules)

    def test_redirect_with_conflict(self):
        self.config.parser.modules.add("rewrite_module")
        ssl_vh = obj.VirtualHost(
            "fp", "ap", set([obj.Addr(("*", "443")), obj.Addr(("zombo.com",))]),
            True, False)
        # No names ^ this guy should conflict.

        # pylint: disable=protected-access
        self.assertRaises(
            errors.PluginError, self.config._enable_redirect, ssl_vh, "")

    def test_redirect_twice(self):
        # Skip the enable mod
        self.config.parser.modules.add("rewrite_module")
        self.config.enhance("encryption-example.demo", "redirect")
        self.assertRaises(
            errors.PluginEnhancementAlreadyPresent,
            self.config.enhance, "encryption-example.demo", "redirect")

    def test_unknown_rewrite(self):
        # Skip the enable mod
        self.config.parser.modules.add("rewrite_module")
        self.config.parser.add_dir(
            self.vh_truth[3].path, "RewriteRule", ["Unknown"])
        self.config.save()
        self.assertRaises(
            errors.PluginError,
            self.config.enhance, "letsencrypt.demo", "redirect")

    def test_unknown_rewrite2(self):
        # Skip the enable mod
        self.config.parser.modules.add("rewrite_module")
        self.config.parser.add_dir(
            self.vh_truth[3].path, "RewriteRule", ["Unknown", "2", "3"])
        self.config.save()
        self.assertRaises(
            errors.PluginError,
            self.config.enhance, "letsencrypt.demo", "redirect")

    def test_unknown_redirect(self):
        # Skip the enable mod
        self.config.parser.modules.add("rewrite_module")
        self.config.parser.add_dir(
            self.vh_truth[3].path, "Redirect", ["Unknown"])
        self.config.save()
        self.assertRaises(
            errors.PluginError,
            self.config.enhance, "letsencrypt.demo", "redirect")

    def test_create_own_redirect(self):
        self.config.parser.modules.add("rewrite_module")
        # For full testing... give names...
        self.vh_truth[1].name = "default.com"
        self.vh_truth[1].aliases = set(["yes.default.com"])

        self.config._enable_redirect(self.vh_truth[1], "")  # pylint: disable=protected-access
        self.assertEqual(len(self.config.vhosts), 7)

    def get_achalls(self):
        """Return testing achallenges."""
        account_key = self.rsa512jwk
        achall1 = achallenges.KeyAuthorizationAnnotatedChallenge(
            challb=acme_util.chall_to_challb(
                challenges.TLSSNI01(
                    token="jIq_Xy1mXGN37tb4L6Xj_es58fW571ZNyXekdZzhh7Q"),
                "pending"),
            domain="encryption-example.demo", account_key=account_key)
        achall2 = achallenges.KeyAuthorizationAnnotatedChallenge(
            challb=acme_util.chall_to_challb(
                challenges.TLSSNI01(
                    token="uqnaPzxtrndteOqtrXb0Asl5gOJfWAnnx6QJyvcmlDU"),
                "pending"),
            domain="letsencrypt.demo", account_key=account_key)

        return account_key, achall1, achall2

    def test_make_addrs_sni_ready(self):
        self.config.version = (2, 2)
        self.config.make_addrs_sni_ready(
            set([obj.Addr.fromstring("*:443"), obj.Addr.fromstring("*:80")]))
        self.assertTrue(self.config.parser.find_dir(
            "NameVirtualHost", "*:80", exclude=False))
        self.assertTrue(self.config.parser.find_dir(
            "NameVirtualHost", "*:443", exclude=False))


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
