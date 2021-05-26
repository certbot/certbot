"""Certbot client."""
# version number like 1.2.3a0, must have at least 2 parts, like 1.2
__version__ = '1.16.0.dev0'

# Compatibility layer for deprecated zope.component processes
import warnings

import zope.component

from certbot.interfaces import IConfig

_original_provide_utility = zope.component.provideUtility
_original_get_utility = zope.component.getUtility


def _provideUtility(component, provides=None, name=u''):
    provided_interfaces = []

    if hasattr(component, '__providedBy__'):
        for interface in getattr(component, '__providedBy__'):
            provided_interfaces.append(interface)

    if provides:
        provided_interfaces.append(provides)

    if IConfig in provided_interfaces:
        warnings.warn("Usage of zope.component.provideUtility for IConfig is deprecated "
                      "and will be removed in a future release.")

    _original_provide_utility(component, provides=provides, name=name)


def _getUtility(interface, name='', context=None):
    if interface == IConfig:
        warnings.warn("Usage of zope.component.getUtility for IConfig is deprecated "
                      "and will be removed in a future release.")

    return _original_get_utility(interface, name=name, context=context)


zope.component.provideUtility = _provideUtility
zope.component.getUtility = _getUtility
