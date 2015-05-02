"""Utilities for plugins discovery and selection."""
import collections
import logging
import pkg_resources

import zope.interface

from letsencrypt.client import constants
from letsencrypt.client import errors
from letsencrypt.client import interfaces

from letsencrypt.client.display import ops as display_ops


class PluginEntryPoint(object):
    """Plugin entry point."""

    PREFIX_FREE_DISTRIBUTIONS = ['letsencrypt']
    """Distributions for which prefix will be omitted."""

    def __init__(self, entry_point):
        self.name = self.entry_point_to_plugin_name(entry_point)
        self.plugin_cls = entry_point.load()
        self.entry_point = entry_point
        self._initialized = None

    @property
    def initialized(self):
        return self._initialized is not None

    @classmethod
    def entry_point_to_plugin_name(cls, entry_point):
        if entry_point.dist.key in cls.PREFIX_FREE_DISTRIBUTIONS:
            return entry_point.name
        return entry_point.dist.key + ':' + entry_point.name

    def init(self, config=None):
        """Memoized plugin inititialization."""
        if not self.initialized:
            self.entry_point.require()  # fetch extras!
            self._initialized = self.plugin_cls(config, self.name)
        return self._initialized

    def __repr__(self):
        return 'PluginEntryPoint#{0}'.format(self.name)


class PluginRegistry(collections.Mapping):
    """Plugin registry."""

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
                'PREFIX_FREE_DISTRIBTIONS messed up')
            plugins[plugin_ep.name] = plugin_ep
        return cls(plugins)

    def filter(self, *ifaces_groups):
        """Filter plugins based on interfaces."""
        return type(self)(dict(
            plugin_ep
            for plugin_ep in self.plugins.iteritems()
            if not ifaces_groups or any(
                all(iface.implementedBy(plugin_ep.plugin_cls)
                    for iface in ifaces)
                for ifaces in ifaces_groups)))

    def __repr__(self):
        return '{0}({1!r})'.format(self.__class__.__name__, self.plugins)

    def __getitem__(self, name):
        return self.plugins[name]

    def __iter__(self):
        return iter(self.plugins)

    def __len__(self):
        return len(self.plugins)


def verify_plugins(initialized, ifaces):
    """Verify plugin objects."""
    verified = {}
    for name, plugin_ep in initialized.iteritems():
        verifies = True
        for iface in ifaces:  # zope.interface.providedBy(plugin)
            try:
                zope.interface.verify.verifyObject(iface, plugin_ep.init())
            except zope.interface.exceptions.BrokenImplementation:
                if iface.implementedBy(plugin_ep.plugin_cls):
                    logging.debug(
                        "%s implements %s but object does "
                        "not verify", plugin_ep.plugin_cls, iface.__name__)
                verifies = False
                break
        if verifies:
            verified[name] = plugin_ep
    return verified


def prepare_plugins(initialized):
    """Prepare plugins."""
    prepared = {}

    for plugin_cls, plugin in initialized.iteritems():
        error = None
        try:
            plugin.prepare()
        except errors.LetsEncryptMisconfigurationError as error:
            logging.debug("Misconfigured %s: %s", plugin, error)
        except errors.LetsEncryptNoInstallationError as error:
            logging.debug("No installation (%s): %s", plugin, error)
            continue
        prepared[plugin_cls] = (plugin, error)

    return prepared  # succefully prepared + misconfigured


def pick_plugin(config, default, ifaces, question):
    plugins = find_plugins()
    names = name_plugins(plugins)

    if default is not None:
        filtered = [names[default]]
    else:
        filtered = filter_plugins(plugins, ifaces)

    initialized = dict((plugin_cls, plugin_cls(config))
                       for plugin_cls in filtered)
    verified = verify_plugins(initialized, ifaces)
    prepared = prepare_plugins(initialized)

    if len(prepared) > 1:
        logging.debug("Multiple candidate plugins: %s", prepared)
        return display_ops.choose_plugin(prepared.values(), question)
    elif len(prepared) == 1:
        logging.debug("Single candidate plugin: %s", prepared)
        return prepared.values()[0]
    else:
        logging.debug("No candidate plugin")
        return None


def pick_authenticator(config, default):
    """Pick authentication plugin."""
    return pick_plugin(
            config, default, (interfaces.IAuthenticator,),
            "How would you like to authenticate with Let's Encrypt CA?")


def pick_installer(config, default):
    """Pick installer plugin."""
    return pick_plugin(config, default, (interfaces.IInstaller,),
                       "How would you like to install certificates?")

def pick_configurator(config, default):
    """Pick configurator plugin."""
    return pick_plugin(
        config, default, (interfaces.IAuthenticator, interfaces.IInstaller),
        "How would you like to install certificates?")
