"""Utilities for plugins discovery and selection."""
import collections
import logging
import pkg_resources

import zope.interface

from letsencrypt.client import constants
from letsencrypt.client import errors
from letsencrypt.client import interfaces

from letsencrypt.client.display import ops as display_ops


def name_plugins(plugins):
    # TODO: actually make it unambiguous...
    names = {}
    for plugin_cls, entry_points in plugins.iteritems():
        entry_point = next(iter(entry_points))  # entry_points.peek()
        names[plugin_cls] = entry_point.name
    return names


def find_plugins():
    """Find plugins using setuptools entry points."""
    plugins = collections.defaultdict(set)
    for entry_point in pkg_resources.iter_entry_points(
            constants.SETUPTOOLS_PLUGINS_ENTRY_POINT):
        plugin_cls = entry_point.load()
        plugins[plugin_cls].add(entry_point)
    return plugins


def filter_plugins(plugins, *ifaces_groups):
    """Filter plugins based on interfaces."""
    return dict(
        (plugin_cls, entry_points)
        for plugin_cls, entry_points in plugins.iteritems()
        if not ifaces_groups or any(
            all(iface.implementedBy(plugin_cls) for iface in ifaces)
            for ifaces in ifaces_groups))


def verify_plugins(initialized, ifaces):
    """Verify plugin objects."""
    verified = {}
    for plugin_cls, plugin in initialized.iteritems():
        verifies = True
        for iface in ifaces:  # zope.interface.providedBy(plugin)
            try:
                zope.interface.verify.verifyObject(iface, plugin)
            except zope.interface.exceptions.BrokenImplementation:
                if iface.implementedBy(plugin_cls):
                    logging.debug(
                        "%s implements %s but object does "
                        "not verify", plugin_cls, iface.__name__)
                verifies = False
                break
        if verifies:
            verified[plugin_cls] = plugin
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
