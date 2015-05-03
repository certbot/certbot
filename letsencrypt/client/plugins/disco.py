"""Utilities for plugins discovery and selection."""
import collections
import logging
import pkg_resources

import zope.interface

from letsencrypt.client import constants
from letsencrypt.client import errors
from letsencrypt.client import interfaces


class PluginEntryPoint(object):
    """Plugin entry point."""

    PREFIX_FREE_DISTRIBUTIONS = ["letsencrypt"]
    """Distributions for which prefix will be omitted."""

    def __init__(self, entry_point):
        self.name = self.entry_point_to_plugin_name(entry_point)
        self.plugin_cls = entry_point.load()
        self.entry_point = entry_point
        self._initialized = None
        self._prepared = None

    @classmethod
    def entry_point_to_plugin_name(cls, entry_point):
        """Unique plugin name for an ``entry_point``"""
        if entry_point.dist.key in cls.PREFIX_FREE_DISTRIBUTIONS:
            return entry_point.name
        return entry_point.dist.key + ":" + entry_point.name

    @property
    def initialized(self):
        """Has the plugin been initialized already?"""
        return self._initialized is not None

    def init(self, config=None):
        """Memoized plugin inititialization."""
        if not self.initialized:
            self.entry_point.require()  # fetch extras!
            self._initialized = self.plugin_cls(config, self.name)
        return self._initialized

    @property
    def prepared(self):
        """Has the plugin been prepared already?"""
        if not self.initialized:
            logging.debug(".prepared called on uninitialized %s", self)
        return self._prepared is not None

    def prepare(self):
        """Memoized plugin preparation."""
        assert self.initialized
        if self._prepared is None:
            try:
                self._initialized.prepare()
            except errors.LetsEncryptMisconfigurationError as error:
                logging.debug("Misconfigured %s: %s", self, error)
                self._prepared = error
            except errors.LetsEncryptNoInstallationError as error:
                logging.debug("No installation (%s): %s", self, error)
                self._prepared = error
            else:
                self._prepared = True
        return self._prepared

    @property
    def misconfigured(self):
        """Is plugin misconfigured?"""
        return isinstance(self._prepared, errors.LetsEncryptMisconfigurationError)

    @property
    def available(self):
        """Is plugin available, i.e. prepared or misconfigured?"""
        return self._prepared is True or self.misconfigured

    def __repr__(self):
        return "PluginEntryPoint#{0}".format(self.name)

    @property
    def name_with_description(self):
        """Name with description. Handy for UI."""
        return "{0} ({1})".format(self.name, self.plugin_cls.description)

    def verify(self, ifaces):
        assert self.initialized
        for iface in ifaces:  # zope.interface.providedBy(plugin)
            try:
                zope.interface.verify.verifyObject(iface, self.init())
            except zope.interface.exceptions.BrokenImplementation:
                if iface.implementedBy(self.plugin_cls):
                    logging.debug(
                        "%s implements %s but object does "
                        "not verify", self.plugin_cls, iface.__name__)
                return False
        return True



class PluginsRegistry(collections.Mapping):
    """Plugins registry."""

    def __init__(self, plugins):
        self.plugins = plugins

    @classmethod
    def find_all(cls):
        """Find plugins using setuptools entry points."""
        plugins = {}
        for entry_point in pkg_resources.iter_entry_points(
                constants.SETUPTOOLS_PLUGINS_ENTRY_POINT):
            plugin_ep = PluginEntryPoint(entry_point)
            assert plugin_ep.name not in plugins, (
                "PREFIX_FREE_DISTRIBUTIONS messed up")
            if interfaces.IPluginFactory.providedBy(plugin_ep.plugin_cls):
                plugins[plugin_ep.name] = plugin_ep
            else:
                logging.warning("Plugin entry point %s does not provide "
                                "IPluginFactory, skipping", plugin_ep)
        return cls(plugins)

    def filter(self, *ifaces_groups):
        """Filter plugins based on interfaces."""
        return type(self)(dict(
            (name, plugin_ep)
            for name, plugin_ep in self.plugins.iteritems()
            if not ifaces_groups or any(
                all(iface.implementedBy(plugin_ep.plugin_cls)
                    for iface in ifaces)
                for ifaces in ifaces_groups)))

    def __repr__(self):
        return "{0}({1!r})".format(
            self.__class__.__name__, set(self.plugins.itervalues()))

    def __getitem__(self, name):
        return self.plugins[name]

    def __iter__(self):
        return iter(self.plugins)

    def __len__(self):
        return len(self.plugins)


def verify_plugins(initialized, ifaces):
    """Verify plugin objects."""
    return dict((name, plugin_ep) for name, plugin_ep in initialized.iteritems()
                if plugin_ep.verify(ifaces))


def available_plugins(initialized):
    """Prepare plugins and filter available."""
    prepared = {}
    for name, plugin_ep in initialized.iteritems():
        plugin_ep.prepare()
        if plugin_ep.available:
            prepared[name] = plugin_ep
    return prepared  # succefully prepared + misconfigured
