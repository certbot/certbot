"""Test for certbot_apache._internal.configurator for CentOS 6 overrides"""
import unittest
from unittest import mock

from certbot.compat import os
from certbot.errors import MisconfigurationError
from certbot_apache._internal import obj
from certbot_apache._internal import override_centos
from certbot_apache._internal import parser
import util


def get_vh_truth(temp_dir, config_name):
    """Return the ground truth for the specified directory."""
    prefix = os.path.join(
        temp_dir, config_name, "httpd/conf.d")

    aug_pre = "/files" + prefix
    vh_truth = [
        obj.VirtualHost(
            os.path.join(prefix, "test.example.com.conf"),
            os.path.join(aug_pre, "test.example.com.conf/VirtualHost"),
            {obj.Addr.fromstring("*:80")},
            False, True, "test.example.com"),
        obj.VirtualHost(
            os.path.join(prefix, "ssl.conf"),
            os.path.join(aug_pre, "ssl.conf/VirtualHost"),
            {obj.Addr.fromstring("_default_:443")},
            True, True, None)
    ]
    return vh_truth

class CentOS6Tests(util.ApacheTest):
    """Tests for CentOS 6"""

    def setUp(self):  # pylint: disable=arguments-differ
        test_dir = "centos6_apache/apache"
        config_root = "centos6_apache/apache/httpd"
        vhost_root = "centos6_apache/apache/httpd/conf.d"
        super().setUp(test_dir=test_dir,
                      config_root=config_root,
                      vhost_root=vhost_root)

        self.config = util.get_apache_configurator(
            self.config_path, self.vhost_path, self.config_dir, self.work_dir,
            version=(2, 2, 15), os_info="centos")
        self.vh_truth = get_vh_truth(
            self.temp_dir, "centos6_apache/apache")

    def test_get_parser(self):
        self.assertIsInstance(self.config.parser, override_centos.CentOSParser)

    def test_get_virtual_hosts(self):
        """Make sure all vhosts are being properly found."""
        vhs = self.config.get_virtual_hosts()
        self.assertEqual(len(vhs), 2)
        found = 0

        for vhost in vhs:
            for centos_truth in self.vh_truth:
                if vhost == centos_truth:
                    found += 1
                    break
            else:
                raise Exception("Missed: %s" % vhost)  # pragma: no cover
        self.assertEqual(found, 2)

    @mock.patch("certbot_apache._internal.configurator.display_util.notify")
    def test_loadmod_default(self, unused_mock_notify):
        ssl_loadmods = self.config.parser.find_dir(
            "LoadModule", "ssl_module", exclude=False)
        self.assertEqual(len(ssl_loadmods), 1)
        # Make sure the LoadModule ssl_module is in ssl.conf (default)
        self.assertIn("ssl.conf", ssl_loadmods[0])
        # ...and that it's not inside of <IfModule>
        self.assertNotIn("IfModule", ssl_loadmods[0])

        # Get the example vhost
        self.config.assoc["test.example.com"] = self.vh_truth[0]
        self.config.deploy_cert(
            "random.demo", "example/cert.pem", "example/key.pem",
            "example/cert_chain.pem", "example/fullchain.pem")
        self.config.save()

        post_loadmods = self.config.parser.find_dir(
            "LoadModule", "ssl_module", exclude=False)

        # We should now have LoadModule ssl_module in root conf and ssl.conf
        self.assertEqual(len(post_loadmods), 2)
        for lm in post_loadmods:
            # lm[:-7] removes "/arg[#]" from the path
            arguments = self.config.parser.get_all_args(lm[:-7])
            self.assertEqual(arguments, ["ssl_module", "modules/mod_ssl.so"])
            # ...and both of them should be wrapped in <IfModule !mod_ssl.c>
            # lm[:-17] strips off /directive/arg[1] from the path.
            ifmod_args = self.config.parser.get_all_args(lm[:-17])
            self.assertIn("!mod_ssl.c", ifmod_args)

    @mock.patch("certbot_apache._internal.configurator.display_util.notify")
    def test_loadmod_multiple(self, unused_mock_notify):
        sslmod_args = ["ssl_module", "modules/mod_ssl.so"]
        # Adds another LoadModule to main httpd.conf in addtition to ssl.conf
        self.config.parser.add_dir(self.config.parser.loc["default"], "LoadModule",
                                   sslmod_args)
        self.config.save()
        pre_loadmods = self.config.parser.find_dir(
            "LoadModule", "ssl_module", exclude=False)
        # LoadModules are not within IfModule blocks
        self.assertIs(any("ifmodule" in m.lower() for m in pre_loadmods), False)
        self.config.assoc["test.example.com"] = self.vh_truth[0]
        self.config.deploy_cert(
            "random.demo", "example/cert.pem", "example/key.pem",
            "example/cert_chain.pem", "example/fullchain.pem")
        post_loadmods = self.config.parser.find_dir(
            "LoadModule", "ssl_module", exclude=False)

        for mod in post_loadmods:
            with self.subTest(mod=mod):
                # pylint: disable=no-member
                self.assertIs(self.config.parser.not_modssl_ifmodule(mod), True)

    @mock.patch("certbot_apache._internal.configurator.display_util.notify")
    def test_loadmod_rootconf_exists(self, unused_mock_notify):
        sslmod_args = ["ssl_module", "modules/mod_ssl.so"]
        rootconf_ifmod = self.config.parser.get_ifmod(
            parser.get_aug_path(self.config.parser.loc["default"]),
            "!mod_ssl.c", beginning=True)
        self.config.parser.add_dir(rootconf_ifmod[:-1], "LoadModule", sslmod_args)
        self.config.save()
        # Get the example vhost
        self.config.assoc["test.example.com"] = self.vh_truth[0]
        self.config.deploy_cert(
            "random.demo", "example/cert.pem", "example/key.pem",
            "example/cert_chain.pem", "example/fullchain.pem")
        self.config.save()

        root_loadmods = self.config.parser.find_dir(
            "LoadModule", "ssl_module",
            start=parser.get_aug_path(self.config.parser.loc["default"]),
            exclude=False)

        mods = [lm for lm in root_loadmods if self.config.parser.loc["default"] in lm]

        self.assertEqual(len(mods), 1)
        # [:-7] removes "/arg[#]" from the path
        self.assertEqual(
            self.config.parser.get_all_args(mods[0][:-7]),
            sslmod_args)

    @mock.patch("certbot_apache._internal.configurator.display_util.notify")
    def test_neg_loadmod_already_on_path(self, unused_mock_notify):
        loadmod_args = ["ssl_module", "modules/mod_ssl.so"]
        ifmod = self.config.parser.get_ifmod(
            self.vh_truth[1].path, "!mod_ssl.c", beginning=True)
        self.config.parser.add_dir(ifmod[:-1], "LoadModule", loadmod_args)
        self.config.parser.add_dir(self.vh_truth[1].path, "LoadModule", loadmod_args)
        self.config.save()
        pre_loadmods = self.config.parser.find_dir(
            "LoadModule", "ssl_module", start=self.vh_truth[1].path, exclude=False)
        self.assertEqual(len(pre_loadmods), 2)
        # The ssl.conf now has two LoadModule directives, one inside of
        # !mod_ssl.c IfModule
        self.config.assoc["test.example.com"] = self.vh_truth[0]
        self.config.deploy_cert(
            "random.demo", "example/cert.pem", "example/key.pem",
            "example/cert_chain.pem", "example/fullchain.pem")
        self.config.save()
        # Ensure that the additional LoadModule wasn't written into the IfModule
        post_loadmods = self.config.parser.find_dir(
            "LoadModule", "ssl_module", start=self.vh_truth[1].path, exclude=False)
        self.assertEqual(len(post_loadmods), 1)

    def test_loadmod_non_duplicate(self):
        # the modules/mod_ssl.so exists in ssl.conf
        sslmod_args = ["ssl_module", "modules/mod_somethingelse.so"]
        rootconf_ifmod = self.config.parser.get_ifmod(
            parser.get_aug_path(self.config.parser.loc["default"]),
            "!mod_ssl.c", beginning=True)
        self.config.parser.add_dir(rootconf_ifmod[:-1], "LoadModule", sslmod_args)
        self.config.save()
        self.config.assoc["test.example.com"] = self.vh_truth[0]
        pre_matches = self.config.parser.find_dir("LoadModule",
                                                  "ssl_module", exclude=False)

        self.assertRaises(MisconfigurationError, self.config.deploy_cert,
                "random.demo", "example/cert.pem", "example/key.pem",
                "example/cert_chain.pem", "example/fullchain.pem")

        post_matches = self.config.parser.find_dir("LoadModule",
                                                   "ssl_module", exclude=False)
        # Make sure that none was changed
        self.assertEqual(pre_matches, post_matches)

    @mock.patch("certbot_apache._internal.configurator.display_util.notify")
    def test_loadmod_not_found(self, unused_mock_notify):
        # Remove all existing LoadModule ssl_module... directives
        orig_loadmods = self.config.parser.find_dir("LoadModule",
                                                    "ssl_module",
                                                    exclude=False)
        for mod in orig_loadmods:
            noarg_path = mod.rpartition("/")[0]
            self.config.parser.aug.remove(noarg_path)
        self.config.save()
        self.config.deploy_cert(
            "random.demo", "example/cert.pem", "example/key.pem",
            "example/cert_chain.pem", "example/fullchain.pem")

        post_loadmods = self.config.parser.find_dir("LoadModule",
                                                    "ssl_module",
                                                    exclude=False)
        self.assertEqual(post_loadmods, [])

    def test_no_ifmod_search_false(self):
        #pylint: disable=no-member

        self.assertIs(self.config.parser.not_modssl_ifmodule(
            "/path/does/not/include/ifmod"
        ), False)
        self.assertIs(self.config.parser.not_modssl_ifmodule(
            ""
        ), False)
        self.assertIs(self.config.parser.not_modssl_ifmodule(
            "/path/includes/IfModule/but/no/arguments"
        ), False)


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
