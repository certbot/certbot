"""Tests for letsencrypt.plugins.selection"""
import sys
from typing import List
import unittest
from unittest import mock

from certbot import errors
from certbot import interfaces
from certbot._internal.display import obj as display_obj
from certbot._internal.plugins.disco import PluginsRegistry
from certbot.display import util as display_util
from certbot.tests import util as test_util


class ConveniencePickPluginTest(unittest.TestCase):
    """Tests for certbot._internal.plugins.selection.pick_*."""

    def _test(self, fun, ifaces):
        config = mock.Mock()
        default = mock.Mock()
        plugins = mock.Mock()

        with mock.patch("certbot._internal.plugins.selection.pick_plugin") as mock_p:
            mock_p.return_value = "foo"
            self.assertEqual("foo", fun(config, default, plugins, "Question?"))
        mock_p.assert_called_once_with(
            config, default, plugins, "Question?", ifaces)

    def test_authenticator(self):
        from certbot._internal.plugins.selection import pick_authenticator
        self._test(pick_authenticator, (interfaces.Authenticator,))

    def test_installer(self):
        from certbot._internal.plugins.selection import pick_installer
        self._test(pick_installer, (interfaces.Installer,))

    def test_configurator(self):
        from certbot._internal.plugins.selection import pick_configurator
        self._test(pick_configurator,
            (interfaces.Authenticator, interfaces.Installer))


class PickPluginTest(unittest.TestCase):
    """Tests for certbot._internal.plugins.selection.pick_plugin."""

    def setUp(self):
        self.config = mock.Mock(noninteractive_mode=False)
        self.default = None
        self.reg = mock.MagicMock()
        self.question = "Question?"
        self.ifaces: List[interfaces.Plugin] = []

    def _call(self):
        from certbot._internal.plugins.selection import pick_plugin
        return pick_plugin(self.config, self.default, self.reg,
                           self.question, self.ifaces)

    def test_default_provided(self):
        self.default = "foo"
        self._call()
        self.assertEqual(1, self.reg.filter.call_count)

    def test_no_default(self):
        self._call()
        self.assertEqual(1, self.reg.visible().ifaces.call_count)

    def test_no_candidate(self):
        self.assertIsNone(self._call())

    def test_single(self):
        plugin_ep = mock.MagicMock()
        plugin_ep.init.return_value = "foo"
        plugin_ep.misconfigured = False

        self.reg.visible().ifaces().available.return_value = {
            "bar": plugin_ep}
        self.assertEqual("foo", self._call())

    def test_single_misconfigured(self):
        plugin_ep = mock.MagicMock()
        plugin_ep.init.return_value = "foo"
        plugin_ep.misconfigured = True

        self.reg.visible().ifaces().available.return_value = {
            "bar": plugin_ep}
        self.assertIsNone(self._call())

    def test_multiple(self):
        plugin_ep = mock.MagicMock()
        plugin_ep.init.return_value = "foo"
        self.reg.visible().ifaces().available.return_value = {
            "bar": plugin_ep,
            "baz": plugin_ep,
        }
        with mock.patch("certbot._internal.plugins.selection.choose_plugin") as mock_choose:
            mock_choose.return_value = plugin_ep
            self.assertEqual("foo", self._call())
        mock_choose.assert_called_once_with(
            [plugin_ep, plugin_ep], self.question)

    def test_choose_plugin_none(self):
        self.reg.visible().ifaces().available.return_value = {
            "bar": None,
            "baz": None,
        }

        with mock.patch("certbot._internal.plugins.selection.choose_plugin") as mock_choose:
            mock_choose.return_value = None
            self.assertIsNone(self._call())


class ChoosePluginTest(unittest.TestCase):
    """Tests for certbot._internal.plugins.selection.choose_plugin."""

    def setUp(self):
        display_obj.set_display(display_obj.FileDisplay(sys.stdout, False))

        self.mock_apache = mock.Mock(
            description_with_name="a", misconfigured=True)
        self.mock_apache.name = "apache"
        self.mock_stand = mock.Mock(
            description_with_name="s", misconfigured=False)
        self.mock_stand.init().more_info.return_value = "standalone"
        self.plugins = [
            self.mock_apache,
            self.mock_stand,
        ]

    def _call(self):
        from certbot._internal.plugins.selection import choose_plugin
        return choose_plugin(self.plugins, "Question?")

    @test_util.patch_display_util()
    def test_selection(self, mock_util):
        mock_util().menu.side_effect = [(display_util.OK, 0),
                                        (display_util.OK, 1)]
        self.assertEqual(self.mock_stand, self._call())
        self.assertEqual(mock_util().notification.call_count, 1)

    @test_util.patch_display_util()
    def test_more_info(self, mock_util):
        mock_util().menu.side_effect = [
            (display_util.OK, 1),
        ]

        self.assertEqual(self.mock_stand, self._call())

    @test_util.patch_display_util()
    def test_no_choice(self, mock_util):
        mock_util().menu.return_value = (display_util.CANCEL, 0)
        self.assertIsNone(self._call())


class GetUnpreparedInstallerTest(test_util.ConfigTestCase):
    """Tests for certbot._internal.plugins.selection.get_unprepared_installer."""

    def setUp(self):
        super().setUp()
        self.mock_apache_fail_ep = mock.Mock(
            description_with_name="afail")
        self.mock_apache_fail_ep.check_name = lambda name: name == "afail"
        self.mock_apache_ep = mock.Mock(
            description_with_name="apache")
        self.mock_apache_ep.check_name = lambda name: name == "apache"
        self.mock_apache_plugin = mock.MagicMock()
        self.mock_apache_ep.init.return_value = self.mock_apache_plugin
        self.plugins = PluginsRegistry({
            "afail": self.mock_apache_fail_ep,
            "apache": self.mock_apache_ep,
        })

    def _call(self):
        from certbot._internal.plugins.selection import get_unprepared_installer
        return get_unprepared_installer(self.config, self.plugins)

    def test_no_installer_defined(self):
        self.config.configurator = None
        self.assertIsNone(self._call())

    def test_no_available_installers(self):
        self.config.configurator = "apache"
        self.plugins = PluginsRegistry({})
        self.assertRaises(errors.PluginSelectionError, self._call)

    def test_get_plugin(self):
        self.config.configurator = "apache"
        installer = self._call()
        self.assertIs(installer, self.mock_apache_plugin)

    def test_multiple_installers_returned(self):
        self.config.configurator = "apache"
        # Two plugins with the same name
        self.mock_apache_fail_ep.check_name = lambda name: name == "apache"
        self.assertRaises(errors.PluginSelectionError, self._call)


class TestChooseConfiguratorPlugins(unittest.TestCase):
    """Tests for certbot._internal.plugins.selection.choose_configurator_plugins."""

    def _setupMockPlugin(self, name):
        mock_ep = mock.Mock(
            description_with_name=name)
        mock_ep.check_name = lambda n: n == name
        mock_plugin = mock.MagicMock()
        mock_plugin.name = name
        mock_ep.init.return_value = mock_plugin
        mock_ep.misconfigured = False
        return mock_ep

    def _parseArgs(self, args):
        from certbot import configuration
        from certbot._internal import cli
        return configuration.NamespaceConfig(
            cli.prepare_and_parse_args(self.plugins, args.split()))

    def setUp(self):
        self.plugins = PluginsRegistry({
            "nginx": self._setupMockPlugin("nginx"),
            "apache": self._setupMockPlugin("apache"),
            "manual": self._setupMockPlugin("manual"),
        })

    def _runWithArgs(self, args):
        from certbot._internal.plugins.selection import choose_configurator_plugins
        return choose_configurator_plugins(self._parseArgs(args), self.plugins, "certonly")

    def test_noninteractive_configurator(self):
        # For certonly, setting either the nginx or apache configurators should
        # return both an installer and authenticator
        inst, auth = self._runWithArgs("certonly --nginx")
        self.assertEqual(inst.name, "nginx")
        self.assertEqual(auth.name, "nginx")

        inst, auth = self._runWithArgs("certonly --apache")
        self.assertEqual(inst.name, "apache")
        self.assertEqual(auth.name, "apache")
    
    def test_noninteractive_inst_arg(self):
        # For certonly, if an installer arg is set, it should be returned as expected
        inst, auth = self._runWithArgs("certonly -a nginx -i nginx")
        self.assertEqual(inst.name, "nginx")
        self.assertEqual(auth.name, "nginx")

        inst, auth = self._runWithArgs("certonly -a apache -i apache")
        self.assertEqual(inst.name, "apache")
        self.assertEqual(auth.name, "apache")

        # if no installer arg is set (or it's set to none), one shouldn't be returned
        inst, auth = self._runWithArgs("certonly -a nginx")
        self.assertEqual(inst, None)
        self.assertEqual(auth.name, "nginx")
        inst, auth = self._runWithArgs("certonly -a nginx -i none")
        self.assertEqual(inst, None)
        self.assertEqual(auth.name, "nginx")

        inst, auth = self._runWithArgs("certonly -a apache")
        self.assertEqual(inst, None)
        self.assertEqual(auth.name, "apache")
        inst, auth = self._runWithArgs("certonly -a apache -i none")
        self.assertEqual(inst, None)
        self.assertEqual(auth.name, "apache")

if __name__ == "__main__":
    unittest.main()  # pragma: no cover
