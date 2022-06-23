"""Tests for certbot._internal.plugins.disco."""
import functools
import string
from typing import List
import unittest
from unittest import mock

import pkg_resources
import zope.interface

from certbot import errors
from certbot import interfaces
from certbot._internal.plugins import null
from certbot._internal.plugins import standalone
from certbot._internal.plugins import webroot


EP_SA = pkg_resources.EntryPoint(
    "sa", "certbot._internal.plugins.standalone",
    attrs=("Authenticator",),
    dist=mock.MagicMock(key="certbot"))
EP_WR = pkg_resources.EntryPoint(
    "wr", "certbot._internal.plugins.webroot",
    attrs=("Authenticator",),
    dist=mock.MagicMock(key="certbot"))


class PluginEntryPointTest(unittest.TestCase):
    """Tests for certbot._internal.plugins.disco.PluginEntryPoint."""

    def setUp(self):
        self.ep1 = pkg_resources.EntryPoint(
            "ep1", "p1.ep1", dist=mock.MagicMock(key="p1"))
        self.ep1prim = pkg_resources.EntryPoint(
            "ep1", "p2.ep2", dist=mock.MagicMock(key="p2"))
        # nested
        self.ep2 = pkg_resources.EntryPoint(
            "ep2", "p2.foo.ep2", dist=mock.MagicMock(key="p2"))
        # project name != top-level package name
        self.ep3 = pkg_resources.EntryPoint(
            "ep3", "a.ep3", dist=mock.MagicMock(key="p3"))

        from certbot._internal.plugins.disco import PluginEntryPoint
        self.plugin_ep = PluginEntryPoint(EP_SA)

    def test_entry_point_to_plugin_name_not_prefixed(self):
        from certbot._internal.plugins.disco import PluginEntryPoint

        names = {
            self.ep1: "ep1",
            self.ep1prim: "ep1",
            self.ep2: "ep2",
            self.ep3: "ep3",
            EP_SA: "sa",
        }

        for entry_point, name in names.items():
            self.assertEqual(
                name, PluginEntryPoint.entry_point_to_plugin_name(entry_point, with_prefix=False))

    def test_entry_point_to_plugin_name_prefixed(self):
        from certbot._internal.plugins.disco import PluginEntryPoint

        names = {
            self.ep1: "p1:ep1",
            self.ep1prim: "p2:ep1",
            self.ep2: "p2:ep2",
            self.ep3: "p3:ep3",
        }

        for entry_point, name in names.items():
            self.assertEqual(
                name, PluginEntryPoint.entry_point_to_plugin_name(entry_point, with_prefix=True))

    def test_description(self):
        self.assertIn("temporary webserver", self.plugin_ep.description)

    def test_description_with_name(self):
        self.plugin_ep.plugin_cls = mock.MagicMock(description="Desc")
        self.assertEqual(
            "Desc (sa)", self.plugin_ep.description_with_name)

    def test_long_description(self):
        self.plugin_ep.plugin_cls = mock.MagicMock(
            long_description="Long desc")
        self.assertEqual(
            "Long desc", self.plugin_ep.long_description)

    def test_long_description_nonexistent(self):
        self.plugin_ep.plugin_cls = mock.MagicMock(
            description="Long desc not found", spec=["description"])
        self.assertEqual(
            "Long desc not found", self.plugin_ep.long_description)

    def test_ifaces(self):
        self.assertTrue(self.plugin_ep.ifaces((interfaces.Authenticator,)))
        self.assertFalse(self.plugin_ep.ifaces((interfaces.Installer,)))
        self.assertFalse(self.plugin_ep.ifaces((
            interfaces.Installer, interfaces.Authenticator)))

    def test__init__(self):
        self.assertIs(self.plugin_ep.initialized, False)
        self.assertIs(self.plugin_ep.prepared, False)
        self.assertIs(self.plugin_ep.misconfigured, False)
        self.assertIs(self.plugin_ep.available, False)
        self.assertIsNone(self.plugin_ep.problem)
        self.assertIs(self.plugin_ep.entry_point, EP_SA)
        self.assertEqual("sa", self.plugin_ep.name)

        self.assertIs(self.plugin_ep.plugin_cls, standalone.Authenticator)

    def test_init(self):
        config = mock.MagicMock()
        plugin = self.plugin_ep.init(config=config)
        self.assertIs(self.plugin_ep.initialized, True)
        self.assertIs(plugin.config, config)
        # memoize!
        self.assertIs(self.plugin_ep.init(), plugin)
        self.assertIs(plugin.config, config)
        # try to give different config
        self.assertIs(self.plugin_ep.init(123), plugin)
        self.assertIs(plugin.config, config)

        self.assertIs(self.plugin_ep.prepared, False)
        self.assertIs(self.plugin_ep.misconfigured, False)
        self.assertIs(self.plugin_ep.available, False)

    def test_verify(self):
        iface1 = mock.MagicMock(__name__="iface1")
        iface2 = mock.MagicMock(__name__="iface2")
        iface3 = mock.MagicMock(__name__="iface3")
        # pylint: disable=protected-access
        self.plugin_ep._initialized = plugin = mock.MagicMock()

        exceptions = zope.interface.exceptions
        with mock.patch("certbot._internal.plugins.disco._verify") as mock_verify:
            mock_verify.exceptions = exceptions

            def verify_object(obj, cls, iface):  # pylint: disable=missing-docstring
                assert obj is plugin
                assert iface is iface1 or iface is iface2 or iface is iface3
                if iface is iface3:
                    return False
                return True
            mock_verify.side_effect = verify_object
            self.assertTrue(self.plugin_ep.verify((iface1,)))
            self.assertTrue(self.plugin_ep.verify((iface1, iface2)))
            self.assertFalse(self.plugin_ep.verify((iface3,)))
            self.assertFalse(self.plugin_ep.verify((iface1, iface3)))

    def test_prepare(self):
        config = mock.MagicMock()
        self.plugin_ep.init(config=config)
        self.plugin_ep.prepare()
        self.assertTrue(self.plugin_ep.prepared)
        self.assertIs(self.plugin_ep.misconfigured, False)

        # output doesn't matter that much, just test if it runs
        str(self.plugin_ep)

    def test_prepare_misconfigured(self):
        plugin = mock.MagicMock()
        plugin.prepare.side_effect = errors.MisconfigurationError
        # pylint: disable=protected-access
        self.plugin_ep._initialized = plugin
        self.assertIsInstance(self.plugin_ep.prepare(),
                                   errors.MisconfigurationError)
        self.assertTrue(self.plugin_ep.prepared)
        self.assertTrue(self.plugin_ep.misconfigured)
        self.assertIsInstance(self.plugin_ep.problem, errors.MisconfigurationError)
        self.assertTrue(self.plugin_ep.available)

    def test_prepare_no_installation(self):
        plugin = mock.MagicMock()
        plugin.prepare.side_effect = errors.NoInstallationError
        # pylint: disable=protected-access
        self.plugin_ep._initialized = plugin
        self.assertIsInstance(self.plugin_ep.prepare(), errors.NoInstallationError)
        self.assertIs(self.plugin_ep.prepared, True)
        self.assertIs(self.plugin_ep.misconfigured, False)
        self.assertIs(self.plugin_ep.available, False)

    def test_prepare_generic_plugin_error(self):
        plugin = mock.MagicMock()
        plugin.prepare.side_effect = errors.PluginError
        # pylint: disable=protected-access
        self.plugin_ep._initialized = plugin
        self.assertIsInstance(self.plugin_ep.prepare(), errors.PluginError)
        self.assertTrue(self.plugin_ep.prepared)
        self.assertIs(self.plugin_ep.misconfigured, False)
        self.assertIs(self.plugin_ep.available, False)

    def test_repr(self):
        self.assertEqual("PluginEntryPoint#sa", repr(self.plugin_ep))


class PluginsRegistryTest(unittest.TestCase):
    """Tests for certbot._internal.plugins.disco.PluginsRegistry."""

    @classmethod
    def _create_new_registry(cls, plugins):
        from certbot._internal.plugins.disco import PluginsRegistry
        return PluginsRegistry(plugins)

    def setUp(self):
        self.plugin_ep = mock.MagicMock()
        self.plugin_ep.name = "mock"
        self.plugin_ep.__hash__.side_effect = TypeError
        self.plugins = {self.plugin_ep.name: self.plugin_ep}
        self.reg = self._create_new_registry(self.plugins)
        self.ep1 = pkg_resources.EntryPoint(
            "ep1", "p1.ep1", dist=mock.MagicMock(key="p1"))

    def test_find_all(self):
        from certbot._internal.plugins.disco import PluginsRegistry
        with mock.patch("certbot._internal.plugins.disco.pkg_resources") as mock_pkg:
            mock_pkg.iter_entry_points.side_effect = [
                iter([EP_SA]), iter([EP_WR, self.ep1])
            ]
            with mock.patch.object(pkg_resources.EntryPoint, 'load') as mock_load:
                mock_load.side_effect = [
                    standalone.Authenticator, webroot.Authenticator,
                    null.Installer, null.Installer]
                plugins = PluginsRegistry.find_all()
        self.assertIs(plugins["sa"].plugin_cls, standalone.Authenticator)
        self.assertIs(plugins["sa"].entry_point, EP_SA)
        self.assertIs(plugins["wr"].plugin_cls, webroot.Authenticator)
        self.assertIs(plugins["wr"].entry_point, EP_WR)
        self.assertIs(plugins["ep1"].plugin_cls, null.Installer)
        self.assertIs(plugins["ep1"].entry_point, self.ep1)
        self.assertIs(plugins["p1:ep1"].plugin_cls, null.Installer)
        self.assertIs(plugins["p1:ep1"].entry_point, self.ep1)

    def test_getitem(self):
        self.assertEqual(self.plugin_ep, self.reg["mock"])

    def test_iter(self):
        self.assertEqual(["mock"], list(self.reg))

    def test_len(self):
        self.assertEqual(0, len(self._create_new_registry({})))
        self.assertEqual(1, len(self.reg))

    def test_init(self):
        self.plugin_ep.init.return_value = "baz"
        self.assertEqual(["baz"], self.reg.init("bar"))
        self.plugin_ep.init.assert_called_once_with("bar")

    def test_filter(self):
        self.assertEqual(
            self.plugins,
            self.reg.filter(lambda p_ep: p_ep.name.startswith("m")))
        self.assertEqual(
            {}, self.reg.filter(lambda p_ep: p_ep.name.startswith("b")))

    def test_ifaces(self):
        self.plugin_ep.ifaces.return_value = True
        # pylint: disable=protected-access
        self.assertEqual(self.plugins, self.reg.ifaces()._plugins)
        self.plugin_ep.ifaces.return_value = False
        self.assertEqual({}, self.reg.ifaces()._plugins)

    def test_verify(self):
        self.plugin_ep.verify.return_value = True
        # pylint: disable=protected-access
        self.assertEqual(
            self.plugins, self.reg.verify(mock.MagicMock())._plugins)
        self.plugin_ep.verify.return_value = False
        self.assertEqual({}, self.reg.verify(mock.MagicMock())._plugins)

    def test_prepare(self):
        self.plugin_ep.prepare.return_value = "baz"
        self.assertEqual(["baz"], self.reg.prepare())
        self.plugin_ep.prepare.assert_called_once_with()

    def test_prepare_order(self):
        order: List[str] = []
        plugins = {
            c: mock.MagicMock(prepare=functools.partial(order.append, c))
            for c in string.ascii_letters
        }
        reg = self._create_new_registry(plugins)
        reg.prepare()
        # order of prepare calls must be sorted to prevent deadlock
        # caused by plugins acquiring locks during prepare
        self.assertEqual(order, sorted(string.ascii_letters))

    def test_available(self):
        self.plugin_ep.available = True
        # pylint: disable=protected-access
        self.assertEqual(self.plugins, self.reg.available()._plugins)
        self.plugin_ep.available = False
        self.assertEqual({}, self.reg.available()._plugins)

    def test_find_init(self):
        self.assertIsNone(self.reg.find_init(mock.Mock()))
        self.plugin_ep.initialized = True
        self.assertIs(
            self.reg.find_init(self.plugin_ep.init()), self.plugin_ep)

    def test_repr(self):
        self.plugin_ep.__repr__ = lambda _: "PluginEntryPoint#mock"
        self.assertEqual("PluginsRegistry(PluginEntryPoint#mock)",
                         repr(self.reg))

    def test_str(self):
        self.assertEqual("No plugins", str(self._create_new_registry({})))
        self.plugin_ep.__str__ = lambda _: "Mock"
        self.assertEqual("Mock", str(self.reg))
        plugins = {self.plugin_ep.name: self.plugin_ep, "foo": "Bar"}
        reg = self._create_new_registry(plugins)
        self.assertEqual("Bar\n\nMock", str(reg))


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
