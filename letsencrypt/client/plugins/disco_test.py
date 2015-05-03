"""Tests for letsencrypt.client.plugins.disco."""
import pkg_resources
import unittest

import mock

from letsencrypt.client.plugins.standalone import authenticator


class PluginEntryPointTest(unittest.TestCase):
    """Tests for letsencrypt.client.plugins.disco.PluginEntryPoint."""

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
        # something we can load()/require()
        self.ep_sa = pkg_resources.EntryPoint(
            "sa", "letsencrypt.client.plugins.standalone.authenticator",
            attrs=('StandaloneAuthenticator',),
            dist=mock.MagicMock(key="letsencrypt"))

        from letsencrypt.client.plugins.disco import PluginEntryPoint
        self.plugin_ep = PluginEntryPoint(self.ep_sa)

    def test__init__(self):
        self.assertFalse(self.plugin_ep.initialized)
        self.assertTrue(self.plugin_ep.entry_point is self.ep_sa)
        self.assertEqual("sa", self.plugin_ep.name)

        self.assertTrue(
            self.plugin_ep.plugin_cls is authenticator.StandaloneAuthenticator)

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

    def test_entry_point_to_plugin_name(self):
        from letsencrypt.client.plugins.disco import PluginEntryPoint

        names = {
            self.ep1: "p1:ep1",
            self.ep1prim: "p2:ep1",
            self.ep2: "p2:ep2",
            self.ep3: "p3:ep3",
            self.ep_sa: "sa",
        }

        for entry_point, name in names.iteritems():
            self.assertEqual(
                name, PluginEntryPoint.entry_point_to_plugin_name(entry_point))

    def test_name_with_description(self):
        self.assertTrue(
            self.plugin_ep.name_with_description.startswith("sa ("))

    def test_repr(self):
        self.assertEqual("PluginEntryPoint#sa", repr(self.plugin_ep))


class PluginsRegistryTest(unittest.TestCase):
    """Tests for letsencrypt.client.plugins.disco.PluginsRegistry."""

    def setUp(self):
        from letsencrypt.client.plugins.disco import PluginsRegistry
        # TODO: mock out pkg_resources.iter_entry_points
        self.plugins = PluginsRegistry.find_all()

    def test_init(self):
        self.assertTrue(self.plugins["standalone"].plugin_cls
                        is authenticator.StandaloneAuthenticator)

    def test_id_filter(self):
        filtered = self.plugins.filter(lambda _: True)
        self.assertEqual(len(self.plugins), len(filtered))

    def test_repr(self):
        repr(self.plugins)


if __name__ == "__main__":
    unittest.main()
