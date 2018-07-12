"""Tests for letsencrypt.plugins.selection"""
import os
import sys
import unittest

import mock
import zope.component

from certbot import errors
from certbot import interfaces

from acme.magic_typing import List  # pylint: disable=unused-import, no-name-in-module
from certbot.display import util as display_util
from certbot.plugins.disco import PluginsRegistry
from certbot.tests import util as test_util


class ConveniencePickPluginTest(unittest.TestCase):
    """Tests for certbot.plugins.selection.pick_*."""

    def _test(self, fun, ifaces):
        config = mock.Mock()
        default = mock.Mock()
        plugins = mock.Mock()

        with mock.patch("certbot.plugins.selection.pick_plugin") as mock_p:
            mock_p.return_value = "foo"
            self.assertEqual("foo", fun(config, default, plugins, "Question?"))
        mock_p.assert_called_once_with(
            config, default, plugins, "Question?", ifaces)

    def test_authenticator(self):
        from certbot.plugins.selection import pick_authenticator
        self._test(pick_authenticator, (interfaces.IAuthenticator,))

    def test_installer(self):
        from certbot.plugins.selection import pick_installer
        self._test(pick_installer, (interfaces.IInstaller,))

    def test_configurator(self):
        from certbot.plugins.selection import pick_configurator
        self._test(pick_configurator,
            (interfaces.IAuthenticator, interfaces.IInstaller))


class PickPluginTest(unittest.TestCase):
    """Tests for certbot.plugins.selection.pick_plugin."""

    def setUp(self):
        self.config = mock.Mock(noninteractive_mode=False)
        self.default = None
        self.reg = mock.MagicMock()
        self.question = "Question?"
        self.ifaces = []  # type: List[interfaces.IPlugin]

    def _call(self):
        from certbot.plugins.selection import pick_plugin
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
        self.assertTrue(self._call() is None)

    def test_single(self):
        plugin_ep = mock.MagicMock()
        plugin_ep.init.return_value = "foo"
        plugin_ep.misconfigured = False

        self.reg.visible().ifaces().verify().available.return_value = {
            "bar": plugin_ep}
        self.assertEqual("foo", self._call())

    def test_single_misconfigured(self):
        plugin_ep = mock.MagicMock()
        plugin_ep.init.return_value = "foo"
        plugin_ep.misconfigured = True

        self.reg.visible().ifaces().verify().available.return_value = {
            "bar": plugin_ep}
        self.assertTrue(self._call() is None)

    def test_multiple(self):
        plugin_ep = mock.MagicMock()
        plugin_ep.init.return_value = "foo"
        self.reg.visible().ifaces().verify().available.return_value = {
            "bar": plugin_ep,
            "baz": plugin_ep,
        }
        with mock.patch("certbot.plugins.selection.choose_plugin") as mock_choose:
            mock_choose.return_value = plugin_ep
            self.assertEqual("foo", self._call())
        mock_choose.assert_called_once_with(
            [plugin_ep, plugin_ep], self.question)

    def test_choose_plugin_none(self):
        self.reg.visible().ifaces().verify().available.return_value = {
            "bar": None,
            "baz": None,
        }

        with mock.patch("certbot.plugins.selection.choose_plugin") as mock_choose:
            mock_choose.return_value = None
            self.assertTrue(self._call() is None)


class ChoosePluginTest(unittest.TestCase):
    """Tests for certbot.plugins.selection.choose_plugin."""

    def setUp(self):
        zope.component.provideUtility(display_util.FileDisplay(sys.stdout,
                                                               False))
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
        from certbot.plugins.selection import choose_plugin
        return choose_plugin(self.plugins, "Question?")

    @test_util.patch_get_utility("certbot.plugins.selection.z_util")
    def test_selection(self, mock_util):
        mock_util().menu.side_effect = [(display_util.OK, 0),
                                        (display_util.OK, 1)]
        self.assertEqual(self.mock_stand, self._call())
        self.assertEqual(mock_util().notification.call_count, 1)

    @test_util.patch_get_utility("certbot.plugins.selection.z_util")
    def test_more_info(self, mock_util):
        mock_util().menu.side_effect = [
            (display_util.OK, 1),
        ]

        self.assertEqual(self.mock_stand, self._call())

    @test_util.patch_get_utility("certbot.plugins.selection.z_util")
    def test_no_choice(self, mock_util):
        mock_util().menu.return_value = (display_util.CANCEL, 0)
        self.assertTrue(self._call() is None)

    @test_util.patch_get_utility("certbot.plugins.selection.z_util")
    def test_new_interaction_avoidance(self, mock_util):
        mock_nginx = mock.Mock(
            description_with_name="n", misconfigured=False)
        mock_nginx.init().more_info.return_value = "nginx plugin"
        mock_nginx.name = "nginx"
        self.plugins[1] = mock_nginx
        mock_util().menu.return_value = (display_util.CANCEL, 0)

        unset_cb_auto = os.environ.get("CERTBOT_AUTO") is None
        if unset_cb_auto:
            os.environ["CERTBOT_AUTO"] = "foo"
        try:
            self._call()
        finally:
            if unset_cb_auto:
                del os.environ["CERTBOT_AUTO"]

        self.assertTrue("default" in mock_util().menu.call_args[1])

class GetUnpreparedInstallerTest(test_util.ConfigTestCase):
    """Tests for certbot.plugins.selection.get_unprepared_installer."""

    def setUp(self):
        super(GetUnpreparedInstallerTest, self).setUp()
        self.mock_apache_fail_ep = mock.Mock(
            description_with_name="afail")
        self.mock_apache_fail_ep.name = "afail"
        self.mock_apache_ep = mock.Mock(
            description_with_name="apache")
        self.mock_apache_ep.name = "apache"
        self.mock_apache_plugin = mock.MagicMock()
        self.mock_apache_ep.init.return_value = self.mock_apache_plugin
        self.plugins = PluginsRegistry({
            "afail": self.mock_apache_fail_ep,
            "apache": self.mock_apache_ep,
        })

    def _call(self):
        from certbot.plugins.selection import get_unprepared_installer
        return get_unprepared_installer(self.config, self.plugins)

    def test_no_installer_defined(self):
        self.config.configurator = None
        self.assertEqual(self._call(), None)

    def test_no_available_installers(self):
        self.config.configurator = "apache"
        self.plugins = PluginsRegistry({})
        self.assertRaises(errors.PluginSelectionError, self._call)

    def test_get_plugin(self):
        self.config.configurator = "apache"
        installer = self._call()
        self.assertTrue(installer is self.mock_apache_plugin)

    def test_multiple_installers_returned(self):
        self.config.configurator = "apache"
        # Two plugins with the same name
        self.mock_apache_fail_ep.name = "apache"
        self.assertRaises(errors.PluginSelectionError, self._call)


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
