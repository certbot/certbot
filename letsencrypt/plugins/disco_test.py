"""Tests for letsencrypt.plugins.disco."""
import pkg_resources
import unittest

import mock
import zope.interface

from letsencrypt import errors
from letsencrypt import interfaces

from letsencrypt.plugins import standalone

EP_SA = pkg_resources.EntryPoint(
    "sa", "letsencrypt.plugins.standalone",
    attrs=("Authenticator",),
    dist=mock.MagicMock(key="letsencrypt"))


class PluginEntryPointTest(unittest.TestCase):
    """Tests for letsencrypt.plugins.disco.PluginEntryPoint."""

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

        from letsencrypt.plugins.disco import PluginEntryPoint
        self.plugin_ep = PluginEntryPoint(EP_SA)

    def test_entry_point_to_plugin_name(self):
        from letsencrypt.plugins.disco import PluginEntryPoint

        names = {
            self.ep1: "p1:ep1",
            self.ep1prim: "p2:ep1",
            self.ep2: "p2:ep2",
            self.ep3: "p3:ep3",
            EP_SA: "sa",
        }

        for entry_point, name in names.iteritems():
            self.assertEqual(
                name, PluginEntryPoint.entry_point_to_plugin_name(entry_point))

    def test_description(self):
        self.assertEqual(
            "Automatically use a temporary webserver",
            self.plugin_ep.description)

    def test_description_with_name(self):
        self.plugin_ep.plugin_cls = mock.MagicMock(description="Desc")
        self.assertEqual(
            "Desc (sa)", self.plugin_ep.description_with_name)

    def test_ifaces(self):
        self.assertTrue(self.plugin_ep.ifaces((interfaces.IAuthenticator,)))
        self.assertFalse(self.plugin_ep.ifaces((interfaces.IInstaller,)))
        self.assertFalse(self.plugin_ep.ifaces((
            interfaces.IInstaller, interfaces.IAuthenticator)))

    def test__init__(self):
        self.assertFalse(self.plugin_ep.initialized)
        self.assertFalse(self.plugin_ep.prepared)
        self.assertFalse(self.plugin_ep.misconfigured)
        self.assertFalse(self.plugin_ep.available)
        self.assertTrue(self.plugin_ep.problem is None)
        self.assertTrue(self.plugin_ep.entry_point is EP_SA)
        self.assertEqual("sa", self.plugin_ep.name)

        self.assertTrue(self.plugin_ep.plugin_cls is standalone.Authenticator)

    def test_init(self):
        config = mock.MagicMock()
        plugin = self.plugin_ep.init(config=config)
        self.assertTrue(self.plugin_ep.initialized)
        self.assertTrue(plugin.config is config)
        # memoize!
        self.assertTrue(self.plugin_ep.init() is plugin)
        self.assertTrue(plugin.config is config)
        # try to give different config
        self.assertTrue(self.plugin_ep.init(123) is plugin)
        self.assertTrue(plugin.config is config)

        self.assertFalse(self.plugin_ep.prepared)
        self.assertFalse(self.plugin_ep.misconfigured)
        self.assertFalse(self.plugin_ep.available)

    def test_verify(self):
        iface1 = mock.MagicMock(__name__="iface1")
        iface2 = mock.MagicMock(__name__="iface2")
        iface3 = mock.MagicMock(__name__="iface3")
        # pylint: disable=protected-access
        self.plugin_ep._initialized = plugin = mock.MagicMock()

        exceptions = zope.interface.exceptions
        with mock.patch("letsencrypt.plugins."
                        "disco.zope.interface") as mock_zope:
            mock_zope.exceptions = exceptions

            def verify_object(iface, obj):  # pylint: disable=missing-docstring
                assert obj is plugin
                assert iface is iface1 or iface is iface2 or iface is iface3
                if iface is iface3:
                    raise mock_zope.exceptions.BrokenImplementation(None, None)
            mock_zope.verify.verifyObject.side_effect = verify_object
            self.assertTrue(self.plugin_ep.verify((iface1,)))
            self.assertTrue(self.plugin_ep.verify((iface1, iface2)))
            self.assertFalse(self.plugin_ep.verify((iface3,)))
            self.assertFalse(self.plugin_ep.verify((iface1, iface3)))

    def test_prepare(self):
        config = mock.MagicMock()
        self.plugin_ep.init(config=config)
        self.plugin_ep.prepare()
        self.assertTrue(self.plugin_ep.prepared)
        self.assertFalse(self.plugin_ep.misconfigured)

        # output doesn't matter that much, just test if it runs
        str(self.plugin_ep)

    def test_prepare_misconfigured(self):
        plugin = mock.MagicMock()
        plugin.prepare.side_effect = errors.MisconfigurationError
        # pylint: disable=protected-access
        self.plugin_ep._initialized = plugin
        self.assertTrue(isinstance(self.plugin_ep.prepare(),
                                   errors.MisconfigurationError))
        self.assertTrue(self.plugin_ep.prepared)
        self.assertTrue(self.plugin_ep.misconfigured)
        self.assertTrue(isinstance(self.plugin_ep.problem,
                                   errors.MisconfigurationError))
        self.assertTrue(self.plugin_ep.available)

    def test_prepare_no_installation(self):
        plugin = mock.MagicMock()
        plugin.prepare.side_effect = errors.NoInstallationError
        # pylint: disable=protected-access
        self.plugin_ep._initialized = plugin
        self.assertTrue(isinstance(self.plugin_ep.prepare(),
                                   errors.NoInstallationError))
        self.assertTrue(self.plugin_ep.prepared)
        self.assertFalse(self.plugin_ep.misconfigured)
        self.assertFalse(self.plugin_ep.available)

    def test_prepare_generic_plugin_error(self):
        plugin = mock.MagicMock()
        plugin.prepare.side_effect = errors.PluginError
        # pylint: disable=protected-access
        self.plugin_ep._initialized = plugin
        self.assertTrue(isinstance(self.plugin_ep.prepare(), errors.PluginError))
        self.assertTrue(self.plugin_ep.prepared)
        self.assertFalse(self.plugin_ep.misconfigured)
        self.assertFalse(self.plugin_ep.available)

    def test_repr(self):
        self.assertEqual("PluginEntryPoint#sa", repr(self.plugin_ep))


class PluginsRegistryTest(unittest.TestCase):
    """Tests for letsencrypt.plugins.disco.PluginsRegistry."""

    def setUp(self):
        from letsencrypt.plugins.disco import PluginsRegistry
        self.plugin_ep = mock.MagicMock(name="mock")
        self.plugin_ep.__hash__.side_effect = TypeError
        self.plugins = {"mock": self.plugin_ep}
        self.reg = PluginsRegistry(self.plugins)

    def test_find_all(self):
        from letsencrypt.plugins.disco import PluginsRegistry
        with mock.patch("letsencrypt.plugins.disco.pkg_resources") as mock_pkg:
            mock_pkg.iter_entry_points.return_value = iter([EP_SA])
            plugins = PluginsRegistry.find_all()
        self.assertTrue(plugins["sa"].plugin_cls is standalone.Authenticator)
        self.assertTrue(plugins["sa"].entry_point is EP_SA)

    def test_getitem(self):
        self.assertEqual(self.plugin_ep, self.reg["mock"])

    def test_iter(self):
        self.assertEqual(["mock"], list(self.reg))

    def test_len(self):
        self.assertEqual(1, len(self.reg))
        self.plugins.clear()
        self.assertEqual(0, len(self.reg))

    def test_init(self):
        self.plugin_ep.init.return_value = "baz"
        self.assertEqual(["baz"], self.reg.init("bar"))
        self.plugin_ep.init.assert_called_once_with("bar")

    def test_filter(self):
        self.plugins.update({
            "foo": "bar",
            "bar": "foo",
            "baz": "boo",
        })
        self.assertEqual(
            {"foo": "bar", "baz": "boo"},
            self.reg.filter(lambda p_ep: str(p_ep).startswith("b")))

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

    def test_available(self):
        self.plugin_ep.available = True
        # pylint: disable=protected-access
        self.assertEqual(self.plugins, self.reg.available()._plugins)
        self.plugin_ep.available = False
        self.assertEqual({}, self.reg.available()._plugins)

    def test_find_init(self):
        self.assertTrue(self.reg.find_init(mock.Mock()) is None)
        self.plugin_ep.initalized = True
        self.assertTrue(
            self.reg.find_init(self.plugin_ep.init()) is self.plugin_ep)

    def test_repr(self):
        self.plugin_ep.__repr__ = lambda _: "PluginEntryPoint#mock"
        self.assertEqual("PluginsRegistry(PluginEntryPoint#mock)",
                         repr(self.reg))

    def test_str(self):
        self.plugin_ep.__str__ = lambda _: "Mock"
        self.plugins["foo"] = "Mock"
        self.assertEqual("Mock\n\nMock", str(self.reg))
        self.plugins.clear()
        self.assertEqual("No plugins", str(self.reg))


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
