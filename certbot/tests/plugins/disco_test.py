"""Tests for certbot._internal.plugins.disco."""
import functools
import string
import sys
from typing import Dict, Union, List
import unittest
from unittest import mock

import pkg_resources
import pytest

from certbot import errors
from certbot import interfaces
from certbot._internal.plugins import null
from certbot._internal.plugins import standalone
from certbot._internal.plugins import webroot
from unittest.mock import MagicMock

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

    def setUp(self) -> None:
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

    def test_entry_point_to_plugin_name_not_prefixed(self) -> None:
        from certbot._internal.plugins.disco import PluginEntryPoint

        names = {
            self.ep1: "ep1",
            self.ep1prim: "ep1",
            self.ep2: "ep2",
            self.ep3: "ep3",
            EP_SA: "sa",
        }

        for entry_point, name in names.items():
            assert name == PluginEntryPoint.entry_point_to_plugin_name(entry_point)

    def test_description(self) -> None:
        assert "server locally" in self.plugin_ep.description

    def test_description_with_name(self) -> None:
        self.plugin_ep.plugin_cls = mock.MagicMock(description="Desc")
        assert "Desc (sa)" == self.plugin_ep.description_with_name

    def test_long_description(self) -> None:
        self.plugin_ep.plugin_cls = mock.MagicMock(
            long_description="Long desc")
        assert "Long desc" == self.plugin_ep.long_description

    def test_long_description_nonexistent(self) -> None:
        self.plugin_ep.plugin_cls = mock.MagicMock(
            description="Long desc not found", spec=["description"])
        assert "Long desc not found" == self.plugin_ep.long_description

    def test_ifaces(self) -> None:
        assert self.plugin_ep.ifaces((interfaces.Authenticator,))
        assert not self.plugin_ep.ifaces((interfaces.Installer,))
        assert not self.plugin_ep.ifaces((
            interfaces.Installer, interfaces.Authenticator))

    def test__init__(self) -> None:
        assert self.plugin_ep.initialized is False
        assert self.plugin_ep.prepared is False
        assert self.plugin_ep.misconfigured is False
        assert self.plugin_ep.available is False
        assert self.plugin_ep.problem is None
        assert self.plugin_ep.entry_point is EP_SA
        assert "sa" == self.plugin_ep.name

        assert self.plugin_ep.plugin_cls is standalone.Authenticator

    def test_init(self) -> None:
        config = mock.MagicMock()
        plugin = self.plugin_ep.init(config=config)
        assert self.plugin_ep.initialized is True
        assert plugin.config is config
        # memoize!
        assert self.plugin_ep.init() is plugin
        assert plugin.config is config
        # try to give different config
        assert self.plugin_ep.init(123) is plugin
        assert plugin.config is config

        assert self.plugin_ep.prepared is False
        assert self.plugin_ep.misconfigured is False
        assert self.plugin_ep.available is False

    def test_prepare(self) -> None:
        config = mock.MagicMock()
        self.plugin_ep.init(config=config)
        self.plugin_ep.prepare()
        assert self.plugin_ep.prepared
        assert self.plugin_ep.misconfigured is False

        # output doesn't matter that much, just test if it runs
        str(self.plugin_ep)

    def test_prepare_misconfigured(self) -> None:
        plugin = mock.MagicMock()
        plugin.prepare.side_effect = errors.MisconfigurationError
        # pylint: disable=protected-access
        self.plugin_ep._initialized = plugin
        assert isinstance(self.plugin_ep.prepare(), errors.MisconfigurationError)
        assert self.plugin_ep.prepared
        assert self.plugin_ep.misconfigured
        assert isinstance(self.plugin_ep.problem, errors.MisconfigurationError)
        assert self.plugin_ep.available

    def test_prepare_no_installation(self) -> None:
        plugin = mock.MagicMock()
        plugin.prepare.side_effect = errors.NoInstallationError
        # pylint: disable=protected-access
        self.plugin_ep._initialized = plugin
        assert isinstance(self.plugin_ep.prepare(), errors.NoInstallationError)
        assert self.plugin_ep.prepared is True
        assert self.plugin_ep.misconfigured is False
        assert self.plugin_ep.available is False

    def test_prepare_generic_plugin_error(self) -> None:
        plugin = mock.MagicMock()
        plugin.prepare.side_effect = errors.PluginError
        # pylint: disable=protected-access
        self.plugin_ep._initialized = plugin
        assert isinstance(self.plugin_ep.prepare(), errors.PluginError)
        assert self.plugin_ep.prepared
        assert self.plugin_ep.misconfigured is False
        assert self.plugin_ep.available is False

    def test_str(self) -> None:
        output = str(self.plugin_ep)
        assert "Authenticator" in output
        assert "Installer" not in output
        assert "Plugin" in output

    def test_repr(self) -> None:
        assert "PluginEntryPoint#sa" == repr(self.plugin_ep)


class PluginsRegistryTest(unittest.TestCase):
    """Tests for certbot._internal.plugins.disco.PluginsRegistry."""

    @classmethod
    def _create_new_registry(cls, plugins: Dict[str, Union[MagicMock, str]]) -> PluginsRegistry:
        from certbot._internal.plugins.disco import PluginsRegistry
        return PluginsRegistry(plugins)

    def setUp(self) -> None:
        self.plugin_ep = mock.MagicMock()
        self.plugin_ep.name = "mock"
        self.plugin_ep.__hash__.side_effect = TypeError
        self.plugins = {self.plugin_ep.name: self.plugin_ep}
        self.reg = self._create_new_registry(self.plugins)
        self.ep1 = pkg_resources.EntryPoint(
            "ep1", "p1.ep1", dist=mock.MagicMock(key="p1"))

    def test_find_all(self) -> None:
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
        assert plugins["sa"].plugin_cls is standalone.Authenticator
        assert plugins["sa"].entry_point is EP_SA
        assert plugins["wr"].plugin_cls is webroot.Authenticator
        assert plugins["wr"].entry_point is EP_WR
        assert plugins["ep1"].plugin_cls is null.Installer
        assert plugins["ep1"].entry_point is self.ep1
        assert "p1:ep1" not in plugins

    def test_getitem(self) -> None:
        assert self.plugin_ep == self.reg["mock"]

    def test_iter(self) -> None:
        assert ["mock"] == list(self.reg)

    def test_len(self) -> None:
        assert 0 == len(self._create_new_registry({}))
        assert 1 == len(self.reg)

    def test_init(self) -> None:
        self.plugin_ep.init.return_value = "baz"
        assert ["baz"] == self.reg.init("bar")
        self.plugin_ep.init.assert_called_once_with("bar")

    def test_filter(self) -> None:
        assert self.plugins == \
            self.reg.filter(lambda p_ep: p_ep.name.startswith("m"))
        assert {} == self.reg.filter(lambda p_ep: p_ep.name.startswith("b"))

    def test_ifaces(self) -> None:
        self.plugin_ep.ifaces.return_value = True
        # pylint: disable=protected-access
        assert self.plugins == self.reg.ifaces()._plugins
        self.plugin_ep.ifaces.return_value = False
        assert {} == self.reg.ifaces()._plugins

    def test_prepare(self) -> None:
        self.plugin_ep.prepare.return_value = "baz"
        assert ["baz"] == self.reg.prepare()
        self.plugin_ep.prepare.assert_called_once_with()

    def test_prepare_order(self) -> None:
        order: List[str] = []
        plugins = {
            c: mock.MagicMock(prepare=functools.partial(order.append, c))
            for c in string.ascii_letters
        }
        reg = self._create_new_registry(plugins)
        reg.prepare()
        # order of prepare calls must be sorted to prevent deadlock
        # caused by plugins acquiring locks during prepare
        assert order == sorted(string.ascii_letters)

    def test_available(self) -> None:
        self.plugin_ep.available = True
        # pylint: disable=protected-access
        assert self.plugins == self.reg.available()._plugins
        self.plugin_ep.available = False
        assert {} == self.reg.available()._plugins

    def test_find_init(self) -> None:
        assert self.reg.find_init(mock.Mock()) is None
        self.plugin_ep.initialized = True
        assert self.reg.find_init(self.plugin_ep.init()) is self.plugin_ep

    def test_repr(self) -> None:
        self.plugin_ep.__repr__ = lambda _: "PluginEntryPoint#mock"
        assert "PluginsRegistry(PluginEntryPoint#mock)" == \
                         repr(self.reg)

    def test_str(self) -> None:
        assert "No plugins" == str(self._create_new_registry({}))
        self.plugin_ep.__str__ = lambda _: "Mock"
        assert "Mock" == str(self.reg)
        plugins = {self.plugin_ep.name: self.plugin_ep, "foo": "Bar"}
        reg = self._create_new_registry(plugins)
        assert "Bar\n\nMock" == str(reg)


if __name__ == "__main__":
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover
