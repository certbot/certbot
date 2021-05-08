"""Certbot client."""
# version number like 1.2.3a0, must have at least 2 parts, like 1.2
__version__ = '1.16.0.dev0'


# Compatibility layer for deprecated zope.component processes
import warnings

import zope.component

from certbot import services
from certbot.interfaces import IConfig
from certbot.interfaces import IDisplay
from certbot.interfaces import IReporter


def _provideUtility(component, provides=None, name=u''):
    provided_interfaces = []

    if hasattr(component, '__providedBy__'):
        for interface in getattr(component, '__providedBy__'):
            provided_interfaces.append(interface)

    if provides:
        provided_interfaces.append(provides)

    if IConfig in provided_interfaces:
        warnings.warn("Usage of zope.component.provideUtility for IConfig is deprecated,"
                      "use certbot.services module instead.")
        services.set_config(component)

    if IDisplay in provided_interfaces:
        warnings.warn("Usage of zope.component.provideUtility for IDisplay is deprecated,"
                      "use certbot.services module instead.")
        services.set_config(component)

    if IReporter in provided_interfaces:
        warnings.warn("Usage of zope.component.provideUtility for IReporter is deprecated,"
                      "use certbot.services module instead.")
        services.set_reporter(component)

    zope.component.provideUtility(component, provides=provides, name=name)


def _getUtility(interface, name='', context=None):
    if interface == IConfig:
        warnings.warn("Usage of zope.component.getUtility for IConfig is deprecated,"
                      "use certbot.services module instead.")
        return services.get_config()

    if interface == IDisplay:
        warnings.warn("Usage of zope.component.getUtility for IDisplay is deprecated,"
                      "use certbot.services module instead.")
        return services.get_display()

    if interface == IReporter:
        warnings.warn("Usage of zope.component.getUtility for IReporter is deprecated,"
                      "use certbot.services module instead.")
        return services.get_reporter()

    return zope.component.getUtility(interface, name=name, context=context)


zope.component.provideUtility = _provideUtility
zope.component.getUtility = _getUtility
