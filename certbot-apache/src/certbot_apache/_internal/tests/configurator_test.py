# pylint: disable=too-many-lines
"""Test for certbot_apache._internal.configurator."""
import copy
import shutil
import socket
import sys
import tempfile
from unittest import mock

import pytest

from acme import challenges, messages
from certbot import achallenges
from certbot import crypto_util
from certbot import errors
from certbot.compat import filesystem
from certbot.compat import os
from certbot.tests import acme_util
from certbot.tests import util as certbot_util
from certbot_apache._internal import apache_util
from certbot_apache._internal import constants
from certbot_apache._internal import obj
from certbot_apache._internal import parser
from certbot_apache._internal.tests import util


class MultipleVhostsTest(util.ApacheTest):
    """Test two standard well-configured HTTP vhosts."""

    def setUp(self):  # pylint: disable=arguments-differ
        super().setUp()

        self.config = util.get_apache_configurator(
            self.config_path, self.vhost_path, self.config_dir, self.work_dir)
        self.config = self.mock_deploy_cert(self.config)
        self.vh_truth = util.get_vh_truth(
            self.temp_dir, "debian_apache_2_4/multiple_vhosts")

    def mock_deploy_cert(self, config):
        """A test for a mock deploy cert"""
        config.real_deploy_cert = self.config.deploy_cert

        def mocked_deploy_cert(*args, **kwargs):
            """a helper to mock a deployed cert"""
            g_mod = "certbot_apache._internal.configurator.ApacheConfigurator.enable_mod"
            with mock.patch(g_mod):
                config.real_deploy_cert(*args, **kwargs)
        self.config.deploy_cert = mocked_deploy_cert
        return self.config

    @mock.patch("certbot_apache._internal.configurator.path_surgery")
    def test_prepare_no_install(self, mock_surgery):
        silly_path = {"PATH": "/tmp/nothingness2342"}
        mock_surgery.return_value = False
        with mock.patch.dict('os.environ', silly_path):
            with pytest.raises(errors.NoInstallationError):
                self.config.prepare()
            assert mock_surgery.call_count == 1

    @mock.patch("certbot_apache._internal.parser.ApacheParser")
    @mock.patch("certbot_apache._internal.configurator.util.exe_exists")
    def test_prepare_version(self, mock_exe_exists, _):
        mock_exe_exists.return_value = True
        self.config.version = None
        self.config.config_test = mock.Mock()
        self.config.get_version = mock.Mock(return_value=(1, 1))

        with pytest.raises(errors.NotSupportedError):
            self.config.prepare()

    def test_prepare_locked(self):
        # It is important to test that server_root is locked during the call to
        # prepare (as opposed to somewhere else during plugin execution) to
        # ensure that this lock will be acquired after the Certbot package
        # acquires all of its locks. (Tests that Certbot calls prepare after
        # acquiring its locks are part of the Certbot package's tests.) Not
        # doing this could result in deadlock from two versions of Certbot that
        # acquire its locks in a different order.
        server_root = self.config.conf("server-root")
        self.config.config_test = mock.Mock()
        os.remove(os.path.join(server_root, ".certbot.lock"))
        certbot_util.lock_and_call(self._test_prepare_locked, server_root)

    @mock.patch("certbot_apache._internal.parser.ApacheParser")
    @mock.patch("certbot_apache._internal.configurator.util.exe_exists")
    @mock.patch("certbot_apache._internal.configurator.ApacheConfigurator.get_parsernode_root")
    def _test_prepare_locked(self, _node, _exists, _parser):
        try:
            self.config.prepare()
        except errors.PluginError as err:
            err_msg = str(err)
            assert "lock" in err_msg
            assert self.config.conf("server-root") in err_msg
        else:  # pragma: no cover
            self.fail("Exception wasn't raised!")

    def test_add_parser_arguments(self):  # pylint: disable=no-self-use
        from certbot_apache._internal.configurator import ApacheConfigurator

        # Weak test..
        ApacheConfigurator.add_parser_arguments(mock.MagicMock())

    def test_docs_parser_arguments(self):
        os.environ["CERTBOT_DOCS"] = "1"
        from certbot_apache._internal.configurator import ApacheConfigurator
        mock_add = mock.MagicMock()
        ApacheConfigurator.add_parser_arguments(mock_add)
        parserargs = ["server_root", "enmod", "dismod", "le_vhost_ext",
                      "vhost_root", "logs_root", "challenge_location",
                      "handle_modules", "handle_sites", "ctl"]
        exp = {}

        for k in ApacheConfigurator.OS_DEFAULTS.__dict__.keys():
            if k in parserargs:
                exp[k.replace("_", "-")] = getattr(ApacheConfigurator.OS_DEFAULTS, k)
        # Special cases
        exp["vhost-root"] = None

        found = set()
        for call in mock_add.call_args_list:
            found.add(call[0][0])

        # Make sure that all (and only) the expected values exist
        assert len(mock_add.call_args_list) == len(found)
        for e in exp:
            with self.subTest(e=e):
                assert e in found

        del os.environ["CERTBOT_DOCS"]

    def test_add_parser_arguments_all_configurators(self):  # pylint: disable=no-self-use
        from certbot_apache._internal.entrypoint import OVERRIDE_CLASSES
        for cls in OVERRIDE_CLASSES.values():
            cls.add_parser_arguments(mock.MagicMock())

    def test_all_configurators_defaults_defined(self):
        from certbot_apache._internal.configurator import ApacheConfigurator
        from certbot_apache._internal.entrypoint import OVERRIDE_CLASSES
        parameters = set(ApacheConfigurator.OS_DEFAULTS.__dict__.keys())
        for cls in OVERRIDE_CLASSES.values():
            assert parameters.issubset(set(cls.OS_DEFAULTS.__dict__.keys())) is True

    def test_constant(self):
        assert "debian_apache_2_4/multiple_vhosts/apache" in self.config.options.server_root

    @certbot_util.patch_display_util()
    def test_get_all_names(self, mock_getutility):
        mock_utility = mock_getutility()
        mock_utility.notification = mock.MagicMock(return_value=True)
        names = self.config.get_all_names()
        assert names == {"certbot.demo", "ocspvhost.com", "encryption-example.demo",
             "nonsym.link", "vhost.in.rootconf", "www.certbot.demo",
             "duplicate.example.com"}

    @certbot_util.patch_display_util()
    @mock.patch("certbot_apache._internal.configurator.socket.gethostbyaddr")
    def test_get_all_names_addrs(self, mock_gethost, mock_getutility):
        mock_gethost.side_effect = [("google.com", "", ""), socket.error]
        mock_utility = mock_getutility()
        mock_utility.notification.return_value = True
        vhost = obj.VirtualHost(
            "fp", "ap",
            {obj.Addr(("8.8.8.8", "443")),
                 obj.Addr(("zombo.com",)),
                 obj.Addr(("192.168.1.2"))},
            True, False)

        self.config.vhosts.append(vhost)

        names = self.config.get_all_names()
        assert len(names) == 9
        assert "zombo.com" in names
        assert "google.com" in names
        assert "certbot.demo" in names

    def test_get_bad_path(self):
        assert apache_util.get_file_path(None) is None
        assert apache_util.get_file_path("nonexistent") is None
        assert self.config._create_vhost("nonexistent") is None # pylint: disable=protected-access

    def test_get_aug_internal_path(self):
        from certbot_apache._internal.apache_util import get_internal_aug_path
        internal_paths = [
            "Virtualhost", "IfModule/VirtualHost", "VirtualHost", "VirtualHost",
            "Macro/VirtualHost", "IfModule/VirtualHost", "VirtualHost",
            "IfModule/VirtualHost"]

        for i, internal_path in enumerate(internal_paths):
            assert get_internal_aug_path(self.vh_truth[i].path) == internal_path

    def test_bad_servername_alias(self):
        ssl_vh1 = obj.VirtualHost(
            "fp1", "ap1", {obj.Addr(("*", "443"))},
            True, False)
        # pylint: disable=protected-access
        self.config._add_servernames(ssl_vh1)
        assert self.config._add_servername_alias("oy_vey", ssl_vh1) is None

    def test_add_servernames_alias(self):
        self.config.parser.add_dir(
            self.vh_truth[2].path, "ServerAlias", ["*.le.co"])
        # pylint: disable=protected-access
        self.config._add_servernames(self.vh_truth[2])
        assert self.vh_truth[2].get_names() == {"*.le.co", "ip-172-30-0-17"}

    def test_get_virtual_hosts(self):
        """Make sure all vhosts are being properly found."""
        vhs = self.config.get_virtual_hosts()
        assert len(vhs) == 12
        found = 0

        for vhost in vhs:
            for truth in self.vh_truth:
                if vhost == truth:
                    found += 1
                    break
            else:
                raise Exception("Missed: %s" % vhost)  # pragma: no cover

        assert found == 12

        # Handle case of non-debian layout get_virtual_hosts
        with mock.patch(
                "certbot_apache._internal.configurator.ApacheConfigurator.conf"
        ) as mock_conf:
            mock_conf.return_value = False
            vhs = self.config.get_virtual_hosts()
            assert len(vhs) == 12

    @mock.patch("certbot_apache._internal.display_ops.select_vhost")
    def test_choose_vhost_none_avail(self, mock_select):
        mock_select.return_value = None
        with pytest.raises(errors.PluginError):
            self.config.choose_vhost("none.com")

    @mock.patch("certbot_apache._internal.display_ops.select_vhost")
    def test_choose_vhost_select_vhost_ssl(self, mock_select):
        mock_select.return_value = self.vh_truth[1]
        assert self.vh_truth[1] == self.config.choose_vhost("none.com")

    @mock.patch("certbot_apache._internal.display_ops.select_vhost")
    @mock.patch("certbot_apache._internal.obj.VirtualHost.conflicts")
    def test_choose_vhost_select_vhost_non_ssl(self, mock_conf, mock_select):
        mock_select.return_value = self.vh_truth[0]
        mock_conf.return_value = False
        chosen_vhost = self.config.choose_vhost("none.com")
        self.vh_truth[0].aliases.add("none.com")
        assert self.vh_truth[0].get_names() == chosen_vhost.get_names()

        # Make sure we go from HTTP -> HTTPS
        assert self.vh_truth[0].ssl is False
        assert chosen_vhost.ssl is True

    @mock.patch("certbot_apache._internal.configurator.ApacheConfigurator._find_best_vhost")
    @mock.patch("certbot_apache._internal.parser.ApacheParser.add_dir")
    def test_choose_vhost_and_servername_addition(self, mock_add, mock_find):
        ret_vh = self.vh_truth[8]
        ret_vh.enabled = False
        mock_find.return_value = self.vh_truth[8]
        self.config.choose_vhost("whatever.com")
        assert mock_add.called is True

    @mock.patch("certbot_apache._internal.display_ops.select_vhost")
    def test_choose_vhost_select_vhost_with_temp(self, mock_select):
        mock_select.return_value = self.vh_truth[0]
        chosen_vhost = self.config.choose_vhost("none.com", create_if_no_ssl=False)
        assert self.vh_truth[0] == chosen_vhost

    @mock.patch("certbot_apache._internal.display_ops.select_vhost")
    def test_choose_vhost_select_vhost_conflicting_non_ssl(self, mock_select):
        mock_select.return_value = self.vh_truth[3]
        conflicting_vhost = obj.VirtualHost(
            "path", "aug_path", {obj.Addr.fromstring("*:443")},
            True, True)
        self.config.vhosts.append(conflicting_vhost)

        with pytest.raises(errors.PluginError):
            self.config.choose_vhost("none.com")

    def test_find_best_http_vhost_default(self):
        vh = obj.VirtualHost(
            "fp", "ap", {obj.Addr.fromstring("_default_:80")}, False, True)
        self.config.vhosts = [vh]
        assert self.config.find_best_http_vhost("foo.bar", False) == vh

    def test_find_best_http_vhost_port(self):
        port = "8080"
        vh = obj.VirtualHost(
            "fp", "ap", {obj.Addr.fromstring("*:" + port)},
            False, True, "encryption-example.demo")
        self.config.vhosts.append(vh)
        assert self.config.find_best_http_vhost("foo.bar", False, port) == vh

    def test_findbest_continues_on_short_domain(self):
        # pylint: disable=protected-access
        assert self.config._find_best_vhost("purple.com") is None

    def test_findbest_continues_on_long_domain(self):
        # pylint: disable=protected-access
        assert self.config._find_best_vhost("green.red.purple.com") is None

    def test_find_best_vhost(self):
        # pylint: disable=protected-access
        assert self.vh_truth[3] == self.config._find_best_vhost("certbot.demo")
        assert self.vh_truth[0] == self.config._find_best_vhost("encryption-example.demo")
        assert self.config._find_best_vhost("does-not-exist.com") is None

    def test_find_best_vhost_variety(self):
        # pylint: disable=protected-access
        ssl_vh = obj.VirtualHost(
            "fp", "ap", {obj.Addr(("*", "443")),
                             obj.Addr(("zombo.com",))},
            True, False)
        self.config.vhosts.append(ssl_vh)
        assert self.config._find_best_vhost("zombo.com") == ssl_vh

    def test_find_best_vhost_default(self):
        # pylint: disable=protected-access
        # Assume only the two default vhosts.
        self.config.vhosts = [
            vh for vh in self.config.vhosts
            if vh.name not in ["certbot.demo", "nonsym.link",
                "encryption-example.demo", "duplicate.example.com",
                "ocspvhost.com", "vhost.in.rootconf"]
            and "*.blue.purple.com" not in vh.aliases
        ]
        assert self.config._find_best_vhost("encryption-example.demo") == \
            self.vh_truth[2]

    def test_non_default_vhosts(self):
        # pylint: disable=protected-access
        vhosts = self.config._non_default_vhosts(self.config.vhosts)
        assert len(vhosts) == 10

    @mock.patch('certbot_apache._internal.configurator.display_util.notify')
    def test_deploy_cert_enable_new_vhost(self, unused_mock_notify):
        # Create
        ssl_vhost = self.config.make_vhost_ssl(self.vh_truth[0])
        self.config.parser.modules["ssl_module"] = None
        self.config.parser.modules["mod_ssl.c"] = None
        self.config.parser.modules["socache_shmcb_module"] = None

        assert ssl_vhost.enabled is False
        self.config.deploy_cert(
            "encryption-example.demo", "example/cert.pem", "example/key.pem",
            "example/cert_chain.pem", "example/fullchain.pem")
        assert ssl_vhost.enabled is True

    def test_no_duplicate_include(self):
        def mock_find_dir(directive, argument, _):
            """Mock method for parser.find_dir"""
            if directive == "Include" and argument.endswith("options-ssl-apache.conf"):
                return ["/path/to/whatever"]
            return None  # pragma: no cover

        mock_add = mock.MagicMock()
        self.config.parser.add_dir = mock_add
        self.config._add_dummy_ssl_directives(self.vh_truth[0])  # pylint: disable=protected-access
        tried_to_add = False
        for a in mock_add.call_args_list:
            if a[0][1] == "Include" and a[0][2] == self.config.mod_ssl_conf:
                tried_to_add = True
        # Include should be added, find_dir is not patched, and returns falsy
        assert tried_to_add is True

        self.config.parser.find_dir = mock_find_dir
        mock_add.reset_mock()
        self.config._add_dummy_ssl_directives(self.vh_truth[0])  # pylint: disable=protected-access
        for a in mock_add.call_args_list:
            if a[0][1] == "Include" and a[0][2] == self.config.mod_ssl_conf:
                self.fail("Include shouldn't be added, as patched find_dir 'finds' existing one") \
                    # pragma: no cover

    @mock.patch('certbot_apache._internal.configurator.display_util.notify')
    def test_deploy_cert(self, unused_mock_notify):
        self.config.parser.modules["ssl_module"] = None
        self.config.parser.modules["mod_ssl.c"] = None
        self.config.parser.modules["socache_shmcb_module"] = None
        # Patch _add_dummy_ssl_directives to make sure we write them correctly
        # pylint: disable=protected-access
        orig_add_dummy = self.config._add_dummy_ssl_directives
        def mock_add_dummy_ssl(vhostpath):
            """Mock method for _add_dummy_ssl_directives"""
            def find_args(path, directive):
                """Return list of arguments in requested directive at path"""
                f_args = []
                dirs = self.config.parser.find_dir(directive, None,
                                                   path)
                for d in dirs:
                    f_args.append(self.config.parser.get_arg(d))
                return f_args
            # Verify that the dummy directives do not exist
            assert "insert_cert_file_path" not in find_args(vhostpath, "SSLCertificateFile")
            assert "insert_key_file_path" not in find_args(vhostpath, "SSLCertificateKeyFile")
            orig_add_dummy(vhostpath)
            # Verify that the dummy directives exist
            assert "insert_cert_file_path" in find_args(vhostpath, "SSLCertificateFile")
            assert "insert_key_file_path" in find_args(vhostpath, "SSLCertificateKeyFile")
        # pylint: disable=protected-access
        self.config._add_dummy_ssl_directives = mock_add_dummy_ssl

        # Get the default 443 vhost
        self.config.assoc["random.demo"] = self.vh_truth[1]
        self.config.deploy_cert(
            "random.demo",
            "example/cert.pem", "example/key.pem", "example/cert_chain.pem")
        self.config.save()

        # Verify ssl_module was enabled.
        assert self.vh_truth[1].enabled is True
        assert "ssl_module" in self.config.parser.modules

        loc_cert = self.config.parser.find_dir(
            "sslcertificatefile", "example/cert.pem", self.vh_truth[1].path)
        loc_key = self.config.parser.find_dir(
            "sslcertificateKeyfile", "example/key.pem", self.vh_truth[1].path)
        loc_chain = self.config.parser.find_dir(
            "SSLCertificateChainFile", "example/cert_chain.pem",
            self.vh_truth[1].path)

        # Verify one directive was found in the correct file
        assert len(loc_cert) == 1
        assert apache_util.get_file_path(loc_cert[0]) == \
            self.vh_truth[1].filep

        assert len(loc_key) == 1
        assert apache_util.get_file_path(loc_key[0]) == \
            self.vh_truth[1].filep

        assert len(loc_chain) == 1
        assert apache_util.get_file_path(loc_chain[0]) == \
            self.vh_truth[1].filep

        # One more time for chain directive setting
        self.config.deploy_cert(
            "random.demo",
            "two/cert.pem", "two/key.pem", "two/cert_chain.pem")
        assert self.config.parser.find_dir(
            "SSLCertificateChainFile", "two/cert_chain.pem",
            self.vh_truth[1].path)

    def test_add_listen_80(self):
        mock_find = mock.Mock()
        mock_add_dir = mock.Mock()
        mock_find.return_value = []
        self.config.parser.find_dir = mock_find
        self.config.parser.add_dir = mock_add_dir
        self.config.ensure_listen("80")
        assert mock_add_dir.called is True
        assert mock_find.called is True
        assert mock_add_dir.call_args[0][1] == "Listen"
        assert mock_add_dir.call_args[0][2] == "80"

    def test_add_listen_80_named(self):
        mock_find = mock.Mock()
        mock_find.return_value = ["test1", "test2", "test3"]
        mock_get = mock.Mock()
        mock_get.side_effect = ["1.2.3.4:80", "[::1]:80", "1.1.1.1:443"]
        mock_add_dir = mock.Mock()

        self.config.parser.find_dir = mock_find
        self.config.parser.get_arg = mock_get
        self.config.parser.add_dir = mock_add_dir

        self.config.ensure_listen("80")
        assert mock_add_dir.call_count == 0

        # Reset return lists and inputs
        mock_add_dir.reset_mock()
        mock_get.side_effect = ["1.2.3.4:80", "[::1]:80", "1.1.1.1:443"]

        # Test
        self.config.ensure_listen("8080")
        assert mock_add_dir.call_count == 3
        assert mock_add_dir.called is True
        assert mock_add_dir.call_args[0][1] == "Listen"
        call_found = False
        for mock_call in mock_add_dir.mock_calls:
            if mock_call[1][2] == ['1.2.3.4:8080']:
                call_found = True
        assert call_found is True

    @mock.patch("certbot_apache._internal.parser.ApacheParser.reset_modules")
    def test_prepare_server_https(self, mock_reset):
        mock_enable = mock.Mock()
        self.config.enable_mod = mock_enable

        mock_find = mock.Mock()
        mock_add_dir = mock.Mock()
        mock_find.return_value = []

        # This will test the Add listen
        self.config.parser.find_dir = mock_find
        self.config.parser.add_dir_to_ifmodssl = mock_add_dir
        self.config.prepare_server_https("443")
        # Changing the order these modules are enabled breaks the reverter
        assert mock_enable.call_args_list[0][0][0] == "socache_shmcb"
        assert mock_enable.call_args[0][0] == "ssl"
        assert mock_enable.call_args[1] == {"temp": False}

        self.config.prepare_server_https("8080", temp=True)
        # Changing the order these modules are enabled breaks the reverter
        assert mock_enable.call_args_list[2][0][0] == "socache_shmcb"
        assert mock_enable.call_args[0][0] == "ssl"
        # Enable mod is temporary
        assert mock_enable.call_args[1] == {"temp": True}

        assert mock_add_dir.call_count == 2

    @mock.patch("certbot_apache._internal.parser.ApacheParser.reset_modules")
    def test_prepare_server_https_named_listen(self, mock_reset):
        mock_find = mock.Mock()
        mock_find.return_value = ["test1", "test2", "test3"]
        mock_get = mock.Mock()
        mock_get.side_effect = ["1.2.3.4:80", "[::1]:80", "1.1.1.1:443"]
        mock_add_dir = mock.Mock()
        mock_enable = mock.Mock()

        self.config.parser.find_dir = mock_find
        self.config.parser.get_arg = mock_get
        self.config.parser.add_dir_to_ifmodssl = mock_add_dir
        self.config.enable_mod = mock_enable

        # Test Listen statements with specific ip listeed
        self.config.prepare_server_https("443")
        # Should be 0 as one interface already listens to 443
        assert mock_add_dir.call_count == 0

        # Reset return lists and inputs
        mock_add_dir.reset_mock()
        mock_get.side_effect = ["1.2.3.4:80", "[::1]:80", "1.1.1.1:443"]

        # Test
        self.config.prepare_server_https("8080", temp=True)
        assert mock_add_dir.call_count == 3
        call_args_list = [mock_add_dir.call_args_list[i][0][2] for i in range(3)]
        assert sorted(call_args_list) == \
            sorted([["1.2.3.4:8080", "https"],
                    ["[::1]:8080", "https"],
                    ["1.1.1.1:8080", "https"]])

        # mock_get.side_effect = ["1.2.3.4:80", "[::1]:80"]
        # mock_find.return_value = ["test1", "test2", "test3"]
        # self.config.parser.get_arg = mock_get
        # self.config.prepare_server_https("8080", temp=True)
        # self.assertEqual(self.listens, 0)

    @mock.patch("certbot_apache._internal.parser.ApacheParser.reset_modules")
    def test_prepare_server_https_needed_listen(self, mock_reset):
        mock_find = mock.Mock()
        mock_find.return_value = ["test1", "test2"]
        mock_get = mock.Mock()
        mock_get.side_effect = ["1.2.3.4:8080", "80"]
        mock_add_dir = mock.Mock()
        mock_enable = mock.Mock()

        self.config.parser.find_dir = mock_find
        self.config.parser.get_arg = mock_get
        self.config.parser.add_dir_to_ifmodssl = mock_add_dir
        self.config.enable_mod = mock_enable

        self.config.prepare_server_https("443")
        assert mock_add_dir.call_count == 1

    @mock.patch("certbot_apache._internal.parser.ApacheParser.reset_modules")
    def test_prepare_server_https_mixed_listen(self, mock_reset):
        mock_find = mock.Mock()
        mock_find.return_value = ["test1", "test2"]
        mock_get = mock.Mock()
        mock_get.side_effect = ["1.2.3.4:8080", "443"]
        mock_add_dir = mock.Mock()
        mock_enable = mock.Mock()

        self.config.parser.find_dir = mock_find
        self.config.parser.get_arg = mock_get
        self.config.parser.add_dir_to_ifmodssl = mock_add_dir
        self.config.enable_mod = mock_enable

        # Test Listen statements with specific ip listeed
        self.config.prepare_server_https("443")
        # Should only be 2 here, as the third interface
        # already listens to the correct port
        assert mock_add_dir.call_count == 0

    def test_make_vhost_ssl_with_mock_span(self):
        # span excludes the closing </VirtualHost> tag in older versions
        # of Augeas
        return_value = [self.vh_truth[0].filep, 1, 12, 0, 0, 0, 1142]
        with mock.patch.object(self.config.parser.aug, 'span') as mock_span:
            mock_span.return_value = return_value
            self.test_make_vhost_ssl()

    def test_make_vhost_ssl_with_mock_span2(self):
        # span includes the closing </VirtualHost> tag in newer versions
        # of Augeas
        return_value = [self.vh_truth[0].filep, 1, 12, 0, 0, 0, 1157]
        with mock.patch.object(self.config.parser.aug, 'span') as mock_span:
            mock_span.return_value = return_value
            self.test_make_vhost_ssl()

    def test_make_vhost_ssl_nonsymlink(self):
        ssl_vhost_slink = self.config.make_vhost_ssl(self.vh_truth[8])
        assert ssl_vhost_slink.ssl is True
        assert ssl_vhost_slink.enabled is True
        assert ssl_vhost_slink.name == "nonsym.link"

    def test_make_vhost_ssl_nonexistent_vhost_path(self):
        ssl_vhost = self.config.make_vhost_ssl(self.vh_truth[1])
        assert os.path.dirname(ssl_vhost.filep) == \
                         os.path.dirname(filesystem.realpath(self.vh_truth[1].filep))

    def test_make_vhost_ssl(self):
        ssl_vhost = self.config.make_vhost_ssl(self.vh_truth[0])

        assert ssl_vhost.filep == \
            os.path.join(self.config_path, "sites-available",
                         "encryption-example-le-ssl.conf")

        assert ssl_vhost.path == \
                         "/files" + ssl_vhost.filep + "/IfModule/Virtualhost"
        assert len(ssl_vhost.addrs) == 1
        assert {obj.Addr.fromstring("*:443")} == ssl_vhost.addrs
        assert ssl_vhost.name == "encryption-example.demo"
        assert ssl_vhost.ssl is True
        assert ssl_vhost.enabled is False

        assert len(self.config.vhosts) == 13

    def test_clean_vhost_ssl(self):
        # pylint: disable=protected-access
        for directive in ["SSLCertificateFile", "SSLCertificateKeyFile",
                          "SSLCertificateChainFile", "SSLCACertificatePath"]:
            for _ in range(10):
                self.config.parser.add_dir(self.vh_truth[1].path,
                                           directive, ["bogus"])
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

        assert len(loc_cert) == 1
        assert len(loc_key) == 1

        assert len(loc_chain) == 0

        assert len(loc_cacert) == 10

    def test_deduplicate_directives(self):
        # pylint: disable=protected-access
        DIRECTIVE = "Foo"
        for _ in range(10):
            self.config.parser.add_dir(self.vh_truth[1].path,
                                       DIRECTIVE, ["bar"])
        self.config.save()

        self.config._deduplicate_directives(self.vh_truth[1].path, [DIRECTIVE])
        self.config.save()

        assert len(self.config.parser.find_dir(
                DIRECTIVE, None, self.vh_truth[1].path, False)) == 1

    def test_remove_directives(self):
        # pylint: disable=protected-access
        DIRECTIVES = ["Foo", "Bar"]
        for directive in DIRECTIVES:
            for _ in range(10):
                self.config.parser.add_dir(self.vh_truth[2].path,
                                           directive, ["baz"])
        self.config.save()

        self.config._remove_directives(self.vh_truth[2].path, DIRECTIVES)
        self.config.save()

        for directive in DIRECTIVES:
            assert len(self.config.parser.find_dir(
                    directive, None, self.vh_truth[2].path, False)) == 0

    def test_make_vhost_ssl_bad_write(self):
        mock_open = mock.mock_open()
        # This calls open
        self.config.reverter.register_file_creation = mock.Mock()
        mock_open.side_effect = IOError
        with mock.patch("builtins.open", mock_open):
            with pytest.raises(errors.PluginError):
                self.config.make_vhost_ssl(self.vh_truth[0])

    def test_get_ssl_vhost_path(self):
        # pylint: disable=protected-access
        assert self.config._get_ssl_vhost_path("example_path").endswith(".conf") is True

    @mock.patch("certbot_apache._internal.configurator.http_01.ApacheHttp01.perform")
    @mock.patch("certbot_apache._internal.configurator.ApacheConfigurator.restart")
    def test_perform(self, mock_restart, mock_http_perform):
        # Only tests functionality specific to configurator.perform
        # Note: As more challenges are offered this will have to be expanded
        account_key, achalls = self.get_key_and_achalls()

        expected = [achall.response(account_key) for achall in achalls]
        mock_http_perform.return_value = expected

        responses = self.config.perform(achalls)

        assert mock_http_perform.call_count == 1
        assert responses == expected

        assert mock_restart.call_count == 1

    @mock.patch("certbot_apache._internal.configurator.ApacheConfigurator.restart")
    @mock.patch("certbot_apache._internal.apache_util._get_runtime_cfg")
    def test_cleanup(self, mock_cfg, mock_restart):
        mock_cfg.return_value = ""
        _, achalls = self.get_key_and_achalls()

        for achall in achalls:
            self.config._chall_out.add(achall)  # pylint: disable=protected-access

        for i, achall in enumerate(achalls):
            self.config.cleanup([achall])
            if i == len(achalls) - 1:
                assert mock_restart.called is True
            else:
                assert mock_restart.called is False

    @mock.patch("certbot_apache._internal.configurator.ApacheConfigurator.restart")
    @mock.patch("certbot_apache._internal.apache_util._get_runtime_cfg")
    def test_cleanup_no_errors(self, mock_cfg, mock_restart):
        mock_cfg.return_value = ""
        _, achalls = self.get_key_and_achalls()
        self.config.http_doer = mock.MagicMock()

        for achall in achalls:
            self.config._chall_out.add(achall)  # pylint: disable=protected-access

        self.config.cleanup([achalls[-1]])
        assert mock_restart.called is False

        self.config.cleanup(achalls)
        assert mock_restart.called is True

    @mock.patch("certbot.util.run_script")
    def test_get_version(self, mock_script):
        mock_script.return_value = (
            "Server Version: Apache/2.4.2 (Debian)", "")
        assert self.config.get_version() == (2, 4, 2)

        mock_script.return_value = (
            "Server Version: Apache/2 (Linux)", "")
        assert self.config.get_version() == (2,)

        mock_script.return_value = (
            "Server Version: Apache (Debian)", "")
        with pytest.raises(errors.PluginError):
            self.config.get_version()

        mock_script.return_value = (
            "Server Version: Apache/2.3{0} Apache/2.4.7".format(
                os.linesep), "")
        with pytest.raises(errors.PluginError):
            self.config.get_version()

        mock_script.side_effect = errors.SubprocessError("Can't find program")
        with pytest.raises(errors.PluginError):
            self.config.get_version()

    @mock.patch("certbot_apache._internal.configurator.util.run_script")
    def test_restart(self, _):
        self.config.restart()

    @mock.patch("certbot_apache._internal.configurator.util.run_script")
    def test_restart_bad_process(self, mock_run_script):
        mock_run_script.side_effect = [None, errors.SubprocessError]

        with pytest.raises(errors.MisconfigurationError):
            self.config.restart()

    @mock.patch("certbot.util.run_script")
    def test_config_test(self, _):
        self.config.config_test()

    @mock.patch("certbot.util.run_script")
    def test_config_test_bad_process(self, mock_run_script):
        mock_run_script.side_effect = errors.SubprocessError

        with pytest.raises(errors.MisconfigurationError):
            self.config.config_test()

    def test_more_info(self):
        assert self.config.more_info()

    def test_get_chall_pref(self):
        assert isinstance(self.config.get_chall_pref(""), list)

    def test_install_ssl_options_conf(self):
        path = os.path.join(self.work_dir, "test_it")
        other_path = os.path.join(self.work_dir, "other_test_it")
        self.config.install_ssl_options_conf(path, other_path)
        assert os.path.isfile(path) is True
        assert os.path.isfile(other_path) is True

    # TEST ENHANCEMENTS
    def test_supported_enhancements(self):
        assert isinstance(self.config.supported_enhancements(), list)

    def test_find_http_vhost_without_ancestor(self):
        # pylint: disable=protected-access
        vhost = self.vh_truth[0]
        vhost.ssl = True
        vhost.ancestor = None
        res = self.config._get_http_vhost(vhost)
        assert self.vh_truth[0].name == res.name
        assert self.vh_truth[0].aliases == res.aliases

    @mock.patch("certbot_apache._internal.configurator.ApacheConfigurator._get_http_vhost")
    @mock.patch("certbot_apache._internal.display_ops.select_vhost")
    @mock.patch("certbot.util.exe_exists")
    def test_enhance_unknown_vhost(self, mock_exe, mock_sel_vhost, mock_get):
        self.config.parser.modules["rewrite_module"] = None
        mock_exe.return_value = True
        ssl_vh1 = obj.VirtualHost(
            "fp1", "ap1", {obj.Addr(("*", "443"))},
            True, False)
        ssl_vh1.name = "satoshi.com"
        self.config.vhosts.append(ssl_vh1)
        mock_sel_vhost.return_value = None
        mock_get.return_value = None

        with pytest.raises(errors.PluginError):
            self.config.enhance("satoshi.com", "redirect")

    def test_enhance_unknown_enhancement(self):
        with pytest.raises(errors.PluginError):
            self.config.enhance("certbot.demo", "unknown_enhancement")

    def test_enhance_no_ssl_vhost(self):
        with mock.patch("certbot_apache._internal.configurator.logger.error") as mock_log:
            with pytest.raises(errors.PluginError):
                self.config.enhance("certbot.demo", "redirect")
            # Check that correct logger.warning was printed
            assert "not able to find" in mock_log.call_args[0][0]
            assert "\"redirect\"" in mock_log.call_args[0][0]

            mock_log.reset_mock()

            with pytest.raises(errors.PluginError):
                self.config.enhance("certbot.demo", "ensure-http-header", "Test")
            # Check that correct logger.warning was printed
            assert "not able to find" in mock_log.call_args[0][0]
            assert "Test" in mock_log.call_args[0][0]

    @mock.patch("certbot.util.exe_exists")
    def test_ocsp_stapling(self, mock_exe):
        self.config.parser.update_runtime_variables = mock.Mock()
        self.config.parser.modules["mod_ssl.c"] = None
        self.config.parser.modules["socache_shmcb_module"] = None
        self.config.get_version = mock.Mock(return_value=(2, 4, 7))
        mock_exe.return_value = True

        # This will create an ssl vhost for certbot.demo
        self.config.choose_vhost("certbot.demo")
        self.config.enhance("certbot.demo", "staple-ocsp")

        # Get the ssl vhost for certbot.demo
        ssl_vhost = self.config.assoc["certbot.demo"]

        ssl_use_stapling_aug_path = self.config.parser.find_dir(
            "SSLUseStapling", "on", ssl_vhost.path)

        assert len(ssl_use_stapling_aug_path) == 1

        ssl_vhost_aug_path = parser.get_aug_path(ssl_vhost.filep)
        stapling_cache_aug_path = self.config.parser.find_dir('SSLStaplingCache',
                    "shmcb:/var/run/apache2/stapling_cache(128000)",
                    ssl_vhost_aug_path)

        assert len(stapling_cache_aug_path) == 1

    @mock.patch("certbot.util.exe_exists")
    def test_ocsp_stapling_twice(self, mock_exe):
        self.config.parser.update_runtime_variables = mock.Mock()
        self.config.parser.modules["mod_ssl.c"] = None
        self.config.parser.modules["socache_shmcb_module"] = None
        self.config.get_version = mock.Mock(return_value=(2, 4, 7))
        mock_exe.return_value = True

        # Checking the case with already enabled ocsp stapling configuration
        self.config.choose_vhost("ocspvhost.com")
        self.config.enhance("ocspvhost.com", "staple-ocsp")

        # Get the ssl vhost for letsencrypt.demo
        ssl_vhost = self.config.assoc["ocspvhost.com"]

        ssl_use_stapling_aug_path = self.config.parser.find_dir(
            "SSLUseStapling", "on", ssl_vhost.path)

        assert len(ssl_use_stapling_aug_path) == 1
        ssl_vhost_aug_path = parser.get_aug_path(ssl_vhost.filep)
        stapling_cache_aug_path = self.config.parser.find_dir('SSLStaplingCache',
                    "shmcb:/var/run/apache2/stapling_cache(128000)",
                    ssl_vhost_aug_path)

        assert len(stapling_cache_aug_path) == 1

    def test_get_http_vhost_third_filter(self):
        ssl_vh = obj.VirtualHost(
            "fp", "ap", {obj.Addr(("*", "443"))},
            True, False)
        ssl_vh.name = "satoshi.com"
        self.config.vhosts.append(ssl_vh)

        # pylint: disable=protected-access
        http_vh = self.config._get_http_vhost(ssl_vh)
        assert http_vh.ssl is False

    @mock.patch("certbot.util.run_script")
    @mock.patch("certbot.util.exe_exists")
    def test_http_header_hsts(self, mock_exe, _):
        self.config.parser.update_runtime_variables = mock.Mock()
        self.config.parser.modules["mod_ssl.c"] = None
        self.config.parser.modules["headers_module"] = None
        mock_exe.return_value = True

        # This will create an ssl vhost for certbot.demo
        self.config.choose_vhost("certbot.demo")
        self.config.enhance("certbot.demo", "ensure-http-header",
                            "Strict-Transport-Security")

        # Get the ssl vhost for certbot.demo
        ssl_vhost = self.config.assoc["certbot.demo"]

        # These are not immediately available in find_dir even with save() and
        # load(). They must be found in sites-available
        hsts_header = self.config.parser.find_dir(
            "Header", None, ssl_vhost.path)

        # four args to HSTS header
        assert len(hsts_header) == 4

    def test_http_header_hsts_twice(self):
        self.config.parser.modules["mod_ssl.c"] = None
        # skip the enable mod
        self.config.parser.modules["headers_module"] = None

        # This will create an ssl vhost for encryption-example.demo
        self.config.choose_vhost("encryption-example.demo")
        self.config.enhance("encryption-example.demo", "ensure-http-header",
                            "Strict-Transport-Security")

        with pytest.raises(errors.PluginEnhancementAlreadyPresent):
            self.config.enhance("encryption-example.demo",
            "ensure-http-header", "Strict-Transport-Security")

    @mock.patch("certbot.util.run_script")
    @mock.patch("certbot.util.exe_exists")
    def test_http_header_uir(self, mock_exe, _):
        self.config.parser.update_runtime_variables = mock.Mock()
        self.config.parser.modules["mod_ssl.c"] = None
        self.config.parser.modules["headers_module"] = None

        mock_exe.return_value = True

        # This will create an ssl vhost for certbot.demo
        self.config.choose_vhost("certbot.demo")
        self.config.enhance("certbot.demo", "ensure-http-header",
                            "Upgrade-Insecure-Requests")

        assert "headers_module" in self.config.parser.modules

        # Get the ssl vhost for certbot.demo
        ssl_vhost = self.config.assoc["certbot.demo"]

        # These are not immediately available in find_dir even with save() and
        # load(). They must be found in sites-available
        uir_header = self.config.parser.find_dir(
            "Header", None, ssl_vhost.path)

        # four args to HSTS header
        assert len(uir_header) == 4

    def test_http_header_uir_twice(self):
        self.config.parser.modules["mod_ssl.c"] = None
        # skip the enable mod
        self.config.parser.modules["headers_module"] = None

        # This will create an ssl vhost for encryption-example.demo
        self.config.choose_vhost("encryption-example.demo")
        self.config.enhance("encryption-example.demo", "ensure-http-header",
                            "Upgrade-Insecure-Requests")

        with pytest.raises(errors.PluginEnhancementAlreadyPresent):
            self.config.enhance("encryption-example.demo",
            "ensure-http-header", "Upgrade-Insecure-Requests")

    @mock.patch("certbot.util.run_script")
    @mock.patch("certbot.util.exe_exists")
    def test_redirect_well_formed_http(self, mock_exe, _):
        self.config.parser.modules["rewrite_module"] = None
        self.config.parser.update_runtime_variables = mock.Mock()
        mock_exe.return_value = True
        self.config.get_version = mock.Mock(return_value=(2, 2))

        # This will create an ssl vhost for certbot.demo
        self.config.choose_vhost("certbot.demo")
        self.config.enhance("certbot.demo", "redirect")

        # These are not immediately available in find_dir even with save() and
        # load(). They must be found in sites-available
        rw_engine = self.config.parser.find_dir(
            "RewriteEngine", "on", self.vh_truth[3].path)
        rw_rule = self.config.parser.find_dir(
            "RewriteRule", None, self.vh_truth[3].path)

        assert len(rw_engine) == 1
        # three args to rw_rule
        assert len(rw_rule) == 3

        # [:-3] to remove the vhost index number
        assert rw_engine[0].startswith(self.vh_truth[3].path[:-3]) is True
        assert rw_rule[0].startswith(self.vh_truth[3].path[:-3]) is True

    def test_rewrite_rule_exists(self):
        # Skip the enable mod
        self.config.parser.modules["rewrite_module"] = None
        self.config.get_version = mock.Mock(return_value=(2, 3, 9))
        self.config.parser.add_dir(
            self.vh_truth[3].path, "RewriteRule", ["Unknown"])
        # pylint: disable=protected-access
        assert self.config._is_rewrite_exists(self.vh_truth[3]) is True

    def test_rewrite_engine_exists(self):
        # Skip the enable mod
        self.config.parser.modules["rewrite_module"] = None
        self.config.get_version = mock.Mock(return_value=(2, 3, 9))
        self.config.parser.add_dir(
            self.vh_truth[3].path, "RewriteEngine", "on")
        # pylint: disable=protected-access
        assert self.config._is_rewrite_engine_on(self.vh_truth[3])

    @mock.patch("certbot.util.run_script")
    @mock.patch("certbot.util.exe_exists")
    def test_redirect_with_existing_rewrite(self, mock_exe, _):
        self.config.parser.modules["rewrite_module"] = None
        self.config.parser.update_runtime_variables = mock.Mock()
        mock_exe.return_value = True
        self.config.get_version = mock.Mock(return_value=(2, 2, 0))

        # Create a preexisting rewrite rule
        self.config.parser.add_dir(
            self.vh_truth[3].path, "RewriteRule", ["UnknownPattern",
                                                   "UnknownTarget"])
        self.config.save()

        # This will create an ssl vhost for certbot.demo
        self.config.choose_vhost("certbot.demo")
        self.config.enhance("certbot.demo", "redirect")

        # These are not immediately available in find_dir even with save() and
        # load(). They must be found in sites-available
        rw_engine = self.config.parser.find_dir(
            "RewriteEngine", "on", self.vh_truth[3].path)
        rw_rule = self.config.parser.find_dir(
            "RewriteRule", None, self.vh_truth[3].path)

        assert len(rw_engine) == 1
        # three args to rw_rule + 1 arg for the pre existing rewrite
        assert len(rw_rule) == 5
        # [:-3] to remove the vhost index number
        assert rw_engine[0].startswith(self.vh_truth[3].path[:-3]) is True
        assert rw_rule[0].startswith(self.vh_truth[3].path[:-3]) is True

        assert "rewrite_module" in self.config.parser.modules

    @mock.patch("certbot.util.run_script")
    @mock.patch("certbot.util.exe_exists")
    def test_redirect_with_old_https_redirection(self, mock_exe, _):
        self.config.parser.modules["rewrite_module"] = None
        self.config.parser.update_runtime_variables = mock.Mock()
        mock_exe.return_value = True
        self.config.get_version = mock.Mock(return_value=(2, 4, 0))

        ssl_vhost = self.config.choose_vhost("certbot.demo")

        # pylint: disable=protected-access
        http_vhost = self.config._get_http_vhost(ssl_vhost)

        # Create an old (previously supported) https redirectoin rewrite rule
        self.config.parser.add_dir(
            http_vhost.path, "RewriteRule",
            ["^",
             "https://%{SERVER_NAME}%{REQUEST_URI}",
             "[L,QSA,R=permanent]"])

        self.config.save()

        try:
            self.config.enhance("certbot.demo", "redirect")
        except errors.PluginEnhancementAlreadyPresent:
            args_paths = self.config.parser.find_dir(
                "RewriteRule", None, http_vhost.path, False)
            arg_vals = [self.config.parser.aug.get(x) for x in args_paths]
            assert arg_vals == constants.REWRITE_HTTPS_ARGS


    def test_redirect_with_conflict(self):
        self.config.parser.modules["rewrite_module"] = None
        ssl_vh = obj.VirtualHost(
            "fp", "ap", {obj.Addr(("*", "443")),
                             obj.Addr(("zombo.com",))},
            True, False)
        # No names ^ this guy should conflict.

        # pylint: disable=protected-access
        with pytest.raises(errors.PluginError):
            self.config._enable_redirect(ssl_vh, "")

    def test_redirect_two_domains_one_vhost(self):
        # Skip the enable mod
        self.config.parser.modules["rewrite_module"] = None
        self.config.get_version = mock.Mock(return_value=(2, 3, 9))

        # Creates ssl vhost for the domain
        self.config.choose_vhost("red.blue.purple.com")

        self.config.enhance("red.blue.purple.com", "redirect")
        verify_no_redirect = ("certbot_apache._internal.configurator."
                              "ApacheConfigurator._verify_no_certbot_redirect")
        with mock.patch(verify_no_redirect) as mock_verify:
            self.config.enhance("green.blue.purple.com", "redirect")
        assert mock_verify.called is False

    def test_redirect_from_previous_run(self):
        # Skip the enable mod
        self.config.parser.modules["rewrite_module"] = None
        self.config.get_version = mock.Mock(return_value=(2, 3, 9))
        self.config.choose_vhost("red.blue.purple.com")
        self.config.enhance("red.blue.purple.com", "redirect")
        # Clear state about enabling redirect on this run
        # pylint: disable=protected-access
        self.config._enhanced_vhosts["redirect"].clear()

        with pytest.raises(errors.PluginEnhancementAlreadyPresent):
            self.config.enhance("green.blue.purple.com", "redirect")

    def test_create_own_redirect(self):
        self.config.parser.modules["rewrite_module"] = None
        self.config.get_version = mock.Mock(return_value=(2, 3, 9))
        # For full testing... give names...
        self.vh_truth[1].name = "default.com"
        self.vh_truth[1].aliases = {"yes.default.com"}

        # pylint: disable=protected-access
        self.config._enable_redirect(self.vh_truth[1], "")
        assert len(self.config.vhosts) == 13

    def test_create_own_redirect_for_old_apache_version(self):
        self.config.parser.modules["rewrite_module"] = None
        self.config.get_version = mock.Mock(return_value=(2, 2))
        # For full testing... give names...
        self.vh_truth[1].name = "default.com"
        self.vh_truth[1].aliases = {"yes.default.com"}

        # pylint: disable=protected-access
        self.config._enable_redirect(self.vh_truth[1], "")
        assert len(self.config.vhosts) == 13

    def test_sift_rewrite_rule(self):
        # pylint: disable=protected-access
        small_quoted_target = "RewriteRule ^ \"http://\""
        assert self.config._sift_rewrite_rule(small_quoted_target) is False

        https_target = "RewriteRule ^ https://satoshi"
        assert self.config._sift_rewrite_rule(https_target) is True

        normal_target = "RewriteRule ^/(.*) http://www.a.com:1234/$1 [L,R]"
        assert self.config._sift_rewrite_rule(normal_target) is False

        not_rewriterule = "NotRewriteRule ^ ..."
        assert self.config._sift_rewrite_rule(not_rewriterule) is False

    def get_key_and_achalls(self):
        """Return testing achallenges."""
        account_key = self.rsa512jwk
        achall1 = achallenges.KeyAuthorizationAnnotatedChallenge(
            challb=acme_util.chall_to_challb(
                challenges.HTTP01(
                    token=b"jIq_Xy1mXGN37tb4L6Xj_es58fW571ZNyXekdZzhh7Q"),
                "pending"),
            identifier=messages.Identifier(typ=messages.IDENTIFIER_FQDN, value="encryption-example.demo"),
            account_key=account_key)
        achall2 = achallenges.KeyAuthorizationAnnotatedChallenge(
            challb=acme_util.chall_to_challb(
                challenges.HTTP01(
                    token=b"uqnaPzxtrndteOqtrXb0Asl5gOJfWAnnx6QJyvcmlDU"),
                "pending"),
            identifier=messages.Identifier(typ=messages.IDENTIFIER_FQDN, value="certbot.demo"),
            account_key=account_key)
        achall3 = achallenges.KeyAuthorizationAnnotatedChallenge(
            challb=acme_util.chall_to_challb(
                challenges.HTTP01(token=(b'x' * 16)), "pending"),
            identifier=messages.Identifier(typ=messages.IDENTIFIER_FQDN, value="example.org"),
            account_key=account_key)

        return account_key, (achall1, achall2, achall3)

    def test_enable_site_nondebian(self):
        inc_path = "/path/to/wherever"
        vhost = self.vh_truth[0]
        vhost.enabled = False
        vhost.filep = inc_path
        assert self.config.parser.find_dir("Include", inc_path) == []
        assert os.path.dirname(inc_path) not in self.config.parser.existing_paths
        self.config.enable_site(vhost)
        assert len(self.config.parser.find_dir("Include", inc_path)) >= 1
        assert os.path.dirname(inc_path) in self.config.parser.existing_paths
        assert os.path.basename(inc_path) in self.config.parser.existing_paths[
                os.path.dirname(inc_path)]

    @mock.patch('certbot_apache._internal.configurator.display_util.notify')
    def test_deploy_cert_not_parsed_path(self, unused_mock_notify):
        # Make sure that we add include to root config for vhosts when
        # handle-sites is false
        self.config.parser.modules["ssl_module"] = None
        self.config.parser.modules["mod_ssl.c"] = None
        self.config.parser.modules["socache_shmcb_module"] = None
        tmp_path = filesystem.realpath(tempfile.mkdtemp("vhostroot"))
        filesystem.chmod(tmp_path, 0o755)
        mock_p = "certbot_apache._internal.configurator.ApacheConfigurator._get_ssl_vhost_path"
        mock_a = "certbot_apache._internal.parser.ApacheParser.add_include"

        with mock.patch(mock_p) as mock_path:
            mock_path.return_value = os.path.join(tmp_path, "whatever.conf")
            with mock.patch(mock_a) as mock_add:
                self.config.deploy_cert(
                    "encryption-example.demo",
                    "example/cert.pem", "example/key.pem",
                    "example/cert_chain.pem")
                # Test that we actually called add_include
                assert mock_add.called is True
        shutil.rmtree(tmp_path)

    def test_deploy_cert_no_mod_ssl(self):
        # Create
        self.config.make_vhost_ssl(self.vh_truth[0])
        self.config.parser.modules["socache_shmcb_module"] = None
        self.config.prepare_server_https = mock.Mock()

        with pytest.raises(errors.MisconfigurationError):
            self.config.deploy_cert("encryption-example.demo", "example/cert.pem", "example/key.pem",
            "example/cert_chain.pem", "example/fullchain.pem")

    @mock.patch("certbot_apache._internal.parser.ApacheParser.parsed_in_original")
    def test_choose_vhost_and_servername_addition_parsed(self, mock_parsed):
        ret_vh = self.vh_truth[8]
        ret_vh.enabled = True
        self.config.enable_site(ret_vh)
        # Make sure that we return early
        assert mock_parsed.called is False

    def test_enable_mod_unsupported(self):
        with pytest.raises(errors.MisconfigurationError):
            self.config.enable_mod("whatever")

    def test_choose_vhosts_wildcard(self):
        # pylint: disable=protected-access
        mock_path = "certbot_apache._internal.display_ops.select_vhost_multiple"
        with mock.patch(mock_path) as mock_select_vhs:
            mock_select_vhs.return_value = [self.vh_truth[3]]
            vhs = self.config._choose_vhosts_wildcard("*.certbot.demo",
                                                     create_ssl=True)
            # Check that the dialog was called with one vh: certbot.demo
            assert mock_select_vhs.call_args[0][0][0] == self.vh_truth[3]
            assert len(mock_select_vhs.call_args_list) == 1

            # And the actual returned values
            assert len(vhs) == 1
            assert vhs[0].name == "certbot.demo"
            assert vhs[0].ssl is True

            assert vhs[0] != self.vh_truth[3]

    @mock.patch("certbot_apache._internal.configurator.ApacheConfigurator.make_vhost_ssl")
    def test_choose_vhosts_wildcard_no_ssl(self, mock_makessl):
        # pylint: disable=protected-access
        mock_path = "certbot_apache._internal.display_ops.select_vhost_multiple"
        with mock.patch(mock_path) as mock_select_vhs:
            mock_select_vhs.return_value = [self.vh_truth[1]]
            vhs = self.config._choose_vhosts_wildcard("*.certbot.demo",
                                                     create_ssl=False)
            assert mock_makessl.called is False
            assert vhs[0] == self.vh_truth[1]

    @mock.patch("certbot_apache._internal.configurator.ApacheConfigurator._vhosts_for_wildcard")
    @mock.patch("certbot_apache._internal.configurator.ApacheConfigurator.make_vhost_ssl")
    def test_choose_vhosts_wildcard_already_ssl(self, mock_makessl, mock_vh_for_w):
        # pylint: disable=protected-access
        # Already SSL vhost
        mock_vh_for_w.return_value = [self.vh_truth[7]]
        mock_path = "certbot_apache._internal.display_ops.select_vhost_multiple"
        with mock.patch(mock_path) as mock_select_vhs:
            mock_select_vhs.return_value = [self.vh_truth[7]]
            vhs = self.config._choose_vhosts_wildcard("whatever",
                                                     create_ssl=True)
            assert mock_select_vhs.call_args[0][0][0] == self.vh_truth[7]
            assert len(mock_select_vhs.call_args_list) == 1
            # Ensure that make_vhost_ssl was not called, vhost.ssl == true
            assert mock_makessl.called is False

            # And the actual returned values
            assert len(vhs) == 1
            assert vhs[0].ssl is True
            assert vhs[0] == self.vh_truth[7]

    @mock.patch('certbot_apache._internal.configurator.display_util.notify')
    def test_deploy_cert_wildcard(self, unused_mock_notify):
        # pylint: disable=protected-access
        mock_choose_vhosts = mock.MagicMock()
        mock_choose_vhosts.return_value = [self.vh_truth[7]]
        self.config._choose_vhosts_wildcard = mock_choose_vhosts
        mock_d = "certbot_apache._internal.configurator.ApacheConfigurator._deploy_cert"
        with mock.patch(mock_d) as mock_dep:
            self.config.deploy_cert("*.wildcard.example.org", "/tmp/path",
                                    "/tmp/path", "/tmp/path", "/tmp/path")
            assert mock_dep.called is True
            assert len(mock_dep.call_args_list) == 1
            assert self.vh_truth[7] == mock_dep.call_args_list[0][0][0]

    @mock.patch("certbot_apache._internal.display_ops.select_vhost_multiple")
    def test_deploy_cert_wildcard_no_vhosts(self, mock_dialog):
        # pylint: disable=protected-access
        mock_dialog.return_value = []
        with pytest.raises(errors.PluginError):
            self.config.deploy_cert("*.wild.cat", "/tmp/path", "/tmp/path",
                           "/tmp/path", "/tmp/path")

    @mock.patch("certbot_apache._internal.configurator.ApacheConfigurator._choose_vhosts_wildcard")
    def test_enhance_wildcard_after_install(self, mock_choose):
        # pylint: disable=protected-access
        self.config.parser.modules["mod_ssl.c"] = None
        self.config.parser.modules["headers_module"] = None
        self.vh_truth[3].ssl = True
        self.config._wildcard_vhosts["*.certbot.demo"] = [self.vh_truth[3]]
        self.config.enhance("*.certbot.demo", "ensure-http-header",
                            "Upgrade-Insecure-Requests")
        assert mock_choose.called is False

    @mock.patch("certbot_apache._internal.configurator.ApacheConfigurator._choose_vhosts_wildcard")
    def test_enhance_wildcard_no_install(self, mock_choose):
        self.vh_truth[3].ssl = True
        mock_choose.return_value = [self.vh_truth[3]]
        self.config.parser.modules["mod_ssl.c"] = None
        self.config.parser.modules["headers_module"] = None
        self.config.enhance("*.certbot.demo", "ensure-http-header",
                            "Upgrade-Insecure-Requests")
        assert mock_choose.called is True

    def test_add_vhost_id(self):
        for vh in [self.vh_truth[0], self.vh_truth[1], self.vh_truth[2]]:
            vh_id = self.config.add_vhost_id(vh)
            assert vh == self.config.find_vhost_by_id(vh_id)

    def test_find_vhost_by_id_404(self):
        with pytest.raises(errors.PluginError):
            self.config.find_vhost_by_id("nonexistent")

    def test_add_vhost_id_already_exists(self):
        first_id = self.config.add_vhost_id(self.vh_truth[0])
        second_id = self.config.add_vhost_id(self.vh_truth[0])
        assert first_id == second_id

    def test_realpath_replaces_symlink(self):
        orig_match = self.config.parser.aug.match
        mock_vhost = copy.deepcopy(self.vh_truth[0])
        mock_vhost.filep = mock_vhost.filep.replace('sites-enabled', u'sites-available')
        mock_vhost.path = mock_vhost.path.replace('sites-enabled', 'sites-available')
        mock_vhost.enabled = False
        self.config.parser.parse_file(mock_vhost.filep)

        def mock_match(aug_expr):
            """Return a mocked match list of VirtualHosts"""
            if "/mocked/path" in aug_expr:
                return [self.vh_truth[1].path, self.vh_truth[0].path, mock_vhost.path]
            return orig_match(aug_expr)

        self.config.parser.parser_paths = ["/mocked/path"]
        self.config.parser.aug.match = mock_match
        vhs = self.config.get_virtual_hosts()
        assert len(vhs) == 2
        assert vhs[0] == self.vh_truth[1]
        # mock_vhost should have replaced the vh_truth[0], because its filepath
        # isn't a symlink
        assert vhs[1] == mock_vhost


class AugeasVhostsTest(util.ApacheTest):
    """Test vhosts with illegal names dependent on augeas version."""
    # pylint: disable=protected-access

    def setUp(self):  # pylint: disable=arguments-differ
        td = "debian_apache_2_4/augeas_vhosts"
        cr = "debian_apache_2_4/augeas_vhosts/apache2"
        vr = "debian_apache_2_4/augeas_vhosts/apache2/sites-available"
        super().setUp(test_dir=td,
                      config_root=cr,
                      vhost_root=vr)

        self.config = util.get_apache_configurator(
            self.config_path, self.vhost_path, self.config_dir,
            self.work_dir)

    def test_choosevhost_with_illegal_name(self):
        self.config.parser.aug = mock.MagicMock()
        self.config.parser.aug.match.side_effect = RuntimeError
        path = "debian_apache_2_4/augeas_vhosts/apache2/sites-available/old-and-default.conf"
        chosen_vhost = self.config._create_vhost(path)
        assert chosen_vhost is None

    def test_choosevhost_works(self):
        path = "debian_apache_2_4/augeas_vhosts/apache2/sites-available/old-and-default.conf"
        chosen_vhost = self.config._create_vhost(path)
        assert chosen_vhost is None or chosen_vhost.path == path

    @mock.patch("certbot_apache._internal.configurator.ApacheConfigurator._create_vhost")
    def test_get_vhost_continue(self, mock_vhost):
        mock_vhost.return_value = None
        vhs = self.config.get_virtual_hosts()
        assert [] == vhs

    def test_choose_vhost_with_matching_wildcard(self):
        names = (
            "an.example.net", "another.example.net", "an.other.example.net")
        for name in names:
            with self.subTest(name=name):
                assert name not in self.config.choose_vhost(name).aliases

    @mock.patch("certbot_apache._internal.obj.VirtualHost.conflicts")
    def test_choose_vhost_without_matching_wildcard(self, mock_conflicts):
        mock_conflicts.return_value = False
        mock_path = "certbot_apache._internal.display_ops.select_vhost"
        with mock.patch(mock_path, lambda _, vhosts: vhosts[0]):
            for name in ("a.example.net", "other.example.net"):
                assert name in self.config.choose_vhost(name).aliases

    @mock.patch("certbot_apache._internal.obj.VirtualHost.conflicts")
    def test_choose_vhost_wildcard_not_found(self, mock_conflicts):
        mock_conflicts.return_value = False
        mock_path = "certbot_apache._internal.display_ops.select_vhost"
        names = (
            "abc.example.net", "not.there.tld", "aa.wildcard.tld"
        )
        with mock.patch(mock_path) as mock_select:
            mock_select.return_value = self.config.vhosts[0]
            for name in names:
                orig_cc = mock_select.call_count
                self.config.choose_vhost(name)
                assert mock_select.call_count - orig_cc == 1

    def test_choose_vhost_wildcard_found(self):
        mock_path = "certbot_apache._internal.display_ops.select_vhost"
        names = (
            "ab.example.net", "a.wildcard.tld", "yetanother.example.net"
        )
        with mock.patch(mock_path) as mock_select:
            mock_select.return_value = self.config.vhosts[0]
            for name in names:
                self.config.choose_vhost(name)
                assert mock_select.call_count == 0

    def test_augeas_span_error(self):
        broken_vhost = self.config.vhosts[0]
        broken_vhost.path = broken_vhost.path + "/nonexistent"
        with pytest.raises(errors.PluginError):
            self.config.make_vhost_ssl(broken_vhost)


class MultiVhostsTest(util.ApacheTest):
    """Test configuration with multiple virtualhosts in a single file."""
    # pylint: disable=protected-access

    def setUp(self):  # pylint: disable=arguments-differ
        td = "debian_apache_2_4/multi_vhosts"
        cr = "debian_apache_2_4/multi_vhosts/apache2"
        vr = "debian_apache_2_4/multi_vhosts/apache2/sites-available"
        super().setUp(test_dir=td, config_root=cr, vhost_root=vr)

        self.config = util.get_apache_configurator(
            self.config_path, self.vhost_path,
            self.config_dir, self.work_dir, conf_vhost_path=self.vhost_path)
        self.vh_truth = util.get_vh_truth(
            self.temp_dir, "debian_apache_2_4/multi_vhosts")

    def test_make_vhost_ssl(self):
        ssl_vhost = self.config.make_vhost_ssl(self.vh_truth[1])

        assert ssl_vhost.filep == \
            os.path.join(self.config_path, "sites-available",
                         "default-le-ssl.conf")

        assert ssl_vhost.path == \
                         "/files" + ssl_vhost.filep + "/IfModule/VirtualHost"
        assert len(ssl_vhost.addrs) == 1
        assert {obj.Addr.fromstring("*:443")} == ssl_vhost.addrs
        assert ssl_vhost.name == "banana.vomit.com"
        assert ssl_vhost.ssl is True
        assert ssl_vhost.enabled is False

        mock_path = "certbot_apache._internal.configurator.ApacheConfigurator._get_new_vh_path"
        with mock.patch(mock_path) as mock_getpath:
            mock_getpath.return_value = None
            with pytest.raises(errors.PluginError):
                self.config.make_vhost_ssl(self.vh_truth[1])

    def test_get_new_path(self):
        with_index_1 = ["/path[1]/section[1]"]
        without_index = ["/path/section"]
        with_index_2 = ["/path[2]/section[2]"]
        assert self.config._get_new_vh_path(without_index, with_index_1) is None
        assert self.config._get_new_vh_path(without_index, with_index_2) == with_index_2[0]

        both = with_index_1 + with_index_2
        assert self.config._get_new_vh_path(without_index, both) == with_index_2[0]

    @mock.patch("certbot_apache._internal.configurator.display_util.notify")
    def test_make_vhost_ssl_with_existing_rewrite_rule(self, mock_notify):
        self.config.parser.modules["rewrite_module"] = None

        ssl_vhost = self.config.make_vhost_ssl(self.vh_truth[4])

        assert self.config.parser.find_dir("RewriteEngine", "on", ssl_vhost.path, False)

        with open(ssl_vhost.filep) as the_file:
            conf_text = the_file.read()
        commented_rewrite_rule = ("# RewriteRule \"^/secrets/(.+)\" "
                                  "\"https://new.example.com/docs/$1\" [R,L]")
        uncommented_rewrite_rule = ("RewriteRule \"^/docs/(.+)\"  "
                                    "\"http://new.example.com/docs/$1\"  [R,L]")
        assert commented_rewrite_rule in conf_text
        assert uncommented_rewrite_rule in conf_text
        assert mock_notify.call_count == 1
        assert "Some rewrite rules" in mock_notify.call_args[0][0]

    @mock.patch("certbot_apache._internal.configurator.display_util.notify")
    def test_make_vhost_ssl_with_existing_rewrite_conds(self, mock_notify):
        self.config.parser.modules["rewrite_module"] = None

        ssl_vhost = self.config.make_vhost_ssl(self.vh_truth[3])

        with open(ssl_vhost.filep) as the_file:
            conf_lines = the_file.readlines()
        conf_line_set = [l.strip() for l in conf_lines]
        not_commented_cond1 = ("RewriteCond "
                "%{DOCUMENT_ROOT}/%{REQUEST_FILENAME} !-f")
        not_commented_rewrite_rule = ("RewriteRule "
            "^(.*)$ b://u%{REQUEST_URI} [P,NE,L]")

        commented_cond1 = "# RewriteCond %{HTTPS} !=on"
        commented_cond2 = "# RewriteCond %{HTTPS} !^$"
        commented_rewrite_rule = ("# RewriteRule ^ "
                                  "https://%{SERVER_NAME}%{REQUEST_URI} "
                                  "[L,NE,R=permanent]")

        assert not_commented_cond1 in conf_line_set
        assert not_commented_rewrite_rule in conf_line_set

        assert commented_cond1 in conf_line_set
        assert commented_cond2 in conf_line_set
        assert commented_rewrite_rule in conf_line_set
        assert mock_notify.call_count == 1
        assert "Some rewrite rules" in mock_notify.call_args[0][0]


class InstallSslOptionsConfTest(util.ApacheTest):
    """Test that the options-ssl-nginx.conf file is installed and updated properly."""

    def setUp(self): # pylint: disable=arguments-differ
        super().setUp()

        self.config = util.get_apache_configurator(
            self.config_path, self.vhost_path, self.config_dir, self.work_dir)

    def _call(self):
        self.config.install_ssl_options_conf(self.config.mod_ssl_conf,
                                             self.config.updated_mod_ssl_conf_digest)

    def _current_ssl_options_hash(self):
        return crypto_util.sha256sum(self.config.pick_apache_config())

    def _assert_current_file(self):
        assert os.path.isfile(self.config.mod_ssl_conf) is True
        assert crypto_util.sha256sum(self.config.mod_ssl_conf) == \
            self._current_ssl_options_hash()

    def test_no_file(self):
        # prepare should have placed a file there
        self._assert_current_file()
        os.remove(self.config.mod_ssl_conf)
        assert os.path.isfile(self.config.mod_ssl_conf) is False
        self._call()
        self._assert_current_file()

    def test_current_file(self):
        self._assert_current_file()
        self._call()
        self._assert_current_file()

    def test_prev_file_updates_to_current(self):
        from certbot_apache._internal.constants import ALL_SSL_OPTIONS_HASHES
        ALL_SSL_OPTIONS_HASHES.insert(0, "test_hash_does_not_match")
        with mock.patch('certbot.crypto_util.sha256sum') as mock_sha256:
            mock_sha256.return_value = ALL_SSL_OPTIONS_HASHES[0]
            self._call()
        self._assert_current_file()

    def test_manually_modified_current_file_does_not_update(self):
        with open(self.config.mod_ssl_conf, "a") as mod_ssl_conf:
            mod_ssl_conf.write("a new line for the wrong hash\n")
        with mock.patch("certbot.plugins.common.logger") as mock_logger:
            self._call()
            assert mock_logger.warning.called is False
        assert os.path.isfile(self.config.mod_ssl_conf) is True
        assert crypto_util.sha256sum(
            self.config.pick_apache_config()) == \
            self._current_ssl_options_hash()
        assert crypto_util.sha256sum(self.config.mod_ssl_conf) != \
            self._current_ssl_options_hash()

    def test_manually_modified_past_file_warns(self):
        with open(self.config.mod_ssl_conf, "a") as mod_ssl_conf:
            mod_ssl_conf.write("a new line for the wrong hash\n")
        with open(self.config.updated_mod_ssl_conf_digest, "w") as f:
            f.write("hashofanoldversion")
        with mock.patch("certbot.plugins.common.logger") as mock_logger:
            self._call()
            assert mock_logger.warning.call_args[0][0] == \
                "%s has been manually modified; updated file " \
                "saved to %s. We recommend updating %s for security purposes."
        assert crypto_util.sha256sum(
            self.config.pick_apache_config()) == \
            self._current_ssl_options_hash()
        # only print warning once
        with mock.patch("certbot.plugins.common.logger") as mock_logger:
            self._call()
            assert mock_logger.warning.called is False

    @mock.patch('certbot_apache._internal.configurator.logger.warning')
    @mock.patch('certbot_apache._internal.configurator.ApacheConfigurator.openssl_version')
    def test_pick_apache_config_versions_and_warnings(self, mock_openssl_version, mock_warning):
        def has_logged_warning():
            """Returns True if a warning was logged about updating Apache."""
            return any('update apache' in call.args[0] for call in mock_warning.call_args_list)

        # old apache, no openssl
        self.config.version = (2, 4, 10)
        mock_openssl_version.return_value = None
        assert 'old' in self.config.pick_apache_config()
        assert not has_logged_warning()

        # old apache, old openssl
        mock_warning.reset_mock()
        mock_openssl_version.return_value = '1.0.2a'
        assert 'old' in self.config.pick_apache_config()
        assert has_logged_warning()

        # old apache, new openssl
        mock_warning.reset_mock()
        mock_openssl_version.return_value = '1.0.2m'
        assert 'old' in self.config.pick_apache_config()
        assert has_logged_warning()

        # new apache, no openssl
        mock_warning.reset_mock()
        self.config.version = (2, 4, 11)
        mock_openssl_version.return_value = None
        assert 'old' in self.config.pick_apache_config()
        assert not has_logged_warning()

        # new apache, old openssl
        mock_warning.reset_mock()
        mock_openssl_version.return_value = '1.0.2a'
        assert 'old' in self.config.pick_apache_config()
        assert has_logged_warning()

        # new apache, new openssl
        mock_warning.reset_mock()
        mock_openssl_version.return_value = '1.0.2m'
        assert 'current' in self.config.pick_apache_config()
        assert not has_logged_warning()

    def test_ssl_config_files_hash_in_all_hashes(self):
        """
        It is really critical that all TLS Apache config files have their SHA256 hash registered in
        constants.ALL_SSL_OPTIONS_HASHES. Otherwise Certbot will mistakenly assume that the config
        file has been manually edited by the user, and will refuse to update it.
        This test ensures that all necessary hashes are present.
        """
        import importlib.resources

        from certbot_apache._internal.constants import ALL_SSL_OPTIONS_HASHES

        ref = importlib.resources.files("certbot_apache") / "_internal" / "tls_configs"
        with importlib.resources.as_file(ref) as tls_configs_dir:
            all_files = [os.path.join(tls_configs_dir, name) for name in os.listdir(tls_configs_dir)
                        if name.endswith('options-ssl-apache.conf')]
            assert len(all_files) >= 1
            for one_file in all_files:
                file_hash = crypto_util.sha256sum(one_file)
                assert file_hash in ALL_SSL_OPTIONS_HASHES, \
                    f"Constants.ALL_SSL_OPTIONS_HASHES must be appended with the sha256 " \
                    f"hash of {one_file} when it is updated."

    def test_openssl_version(self):
        self.config._openssl_version = None
        some_string_contents = b"""
            SSLOpenSSLConfCmd
            OpenSSL configuration command
            SSLv3 not supported by this version of OpenSSL
            '%s': invalid OpenSSL configuration command
            OpenSSL 1.0.2g  1 Mar 2016
            OpenSSL
            AH02407: "SSLOpenSSLConfCmd %s %s" failed for %s
            AH02556: "SSLOpenSSLConfCmd %s %s" applied to %s
            OpenSSL 1.0.2g  1 Mar 2016
            """
        # ssl_module as a DSO
        self.config.parser.modules['ssl_module'] = '/fake/path'
        with mock.patch("certbot_apache._internal.configurator."
            "ApacheConfigurator._open_module_file") as mock_omf:
            mock_omf.return_value = some_string_contents
            assert self.config.openssl_version() == "1.0.2g"

        # ssl_module statically linked
        self.config._openssl_version = None
        self.config.parser.modules['ssl_module'] = None
        self.config.options.bin = '/fake/path/to/httpd'
        with mock.patch("certbot_apache._internal.configurator."
            "ApacheConfigurator._open_module_file") as mock_omf:
            mock_omf.return_value = some_string_contents
            assert self.config.openssl_version() == "1.0.2g"

    def test_openssl_version_warns(self):
        self.config._openssl_version = '1.0.2a'
        assert self.config.openssl_version() == '1.0.2a'

        self.config._openssl_version = None
        with mock.patch("certbot_apache._internal.configurator.logger.warning") as mock_log:
            assert self.config.openssl_version() is None
            assert "Could not find ssl_module" in mock_log.call_args[0][0]

        # When no ssl_module is present at all
        self.config._openssl_version = None
        assert "ssl_module" not in self.config.parser.modules
        with mock.patch("certbot_apache._internal.configurator.logger.warning") as mock_log:
            assert self.config.openssl_version() is None
            assert "Could not find ssl_module" in mock_log.call_args[0][0]

        # When ssl_module is statically linked but --apache-bin not provided
        self.config._openssl_version = None
        self.config.options.bin = None
        self.config.parser.modules['ssl_module'] = None
        with mock.patch("certbot_apache._internal.configurator.logger.warning") as mock_log:
            assert self.config.openssl_version() is None
            assert "ssl_module is statically linked but" in mock_log.call_args[0][0]

        self.config.parser.modules['ssl_module'] = "/fake/path"
        with mock.patch("certbot_apache._internal.configurator.logger.warning") as mock_log:
            # Check that correct logger.warning was printed
            assert self.config.openssl_version() is None
            assert "Unable to read" in mock_log.call_args[0][0]

        contents_missing_openssl = b"these contents won't match the regex"
        with mock.patch("certbot_apache._internal.configurator."
            "ApacheConfigurator._open_module_file") as mock_omf:
            mock_omf.return_value = contents_missing_openssl
            with mock.patch("certbot_apache._internal.configurator.logger.warning") as mock_log:
                # Check that correct logger.warning was printed
                assert self.config.openssl_version() is None
                assert "Could not find OpenSSL" in mock_log.call_args[0][0]

    def test_open_module_file(self):
        mock_open = mock.mock_open(read_data="testing 12 3")
        with mock.patch("builtins.open", mock_open):
            assert self.config._open_module_file("/nonsense/") == "testing 12 3"

if __name__ == "__main__":
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover
