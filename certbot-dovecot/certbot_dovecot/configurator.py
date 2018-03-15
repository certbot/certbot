"""Dovecot Configuration"""
import zope.interface

from certbot import interfaces

from certbot.plugins import common


@zope.interface.implementer(interfaces.IInstaller)
class DovecotConfigurator(common.Installer):
    """Dovecot configurator."""
