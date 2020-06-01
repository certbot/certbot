##############################################################################
#
# Copyright (c) 2005 Zope Foundation and Contributors.
# All Rights Reserved.
#
# This software is subject to the provisions of the Zope Public License,
# Version 2.1 (ZPL).  A copy of the ZPL should accompany this distribution.
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL EXPRESS OR IMPLIED
# WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND FITNESS
# FOR A PARTICULAR PURPOSE.
#
##############################################################################
"""zope.security support for the configuration handlers
"""
from zope.interface import providedBy
from zope.proxy import ProxyBase
from zope.proxy import getProxiedObject
from zope.security.adapter import LocatingTrustedAdapterFactory
from zope.security.adapter import LocatingUntrustedAdapterFactory
from zope.security.adapter import TrustedAdapterFactory
from zope.security.checker import Checker
from zope.security.checker import CheckerPublic
from zope.security.checker import InterfaceChecker
from zope.security.proxy import Proxy


PublicPermission = 'zope.Public'

class PermissionProxy(ProxyBase):

    __slots__ = ('__Security_checker__', )

    def __providedBy__(self):
        return providedBy(getProxiedObject(self))
    __providedBy__ = property(__providedBy__)

def _checker(_context, permission, allowed_interface, allowed_attributes):
    if (not allowed_attributes) and (not allowed_interface):
        allowed_attributes = ["__call__"]

    if permission == PublicPermission:
        permission = CheckerPublic

    require={}
    if allowed_attributes:
        for name in allowed_attributes:
            require[name] = permission
    if allowed_interface:
        for i in allowed_interface:
            for name in i.names(all=True):
                require[name] = permission

    checker = Checker(require)
    return checker

def proxify(ob, checker=None, provides=None, permission=None):
    """Try to get the object proxied with the `checker`, but not too soon

    We really don't want to proxy the object unless we need to.
    """

    if checker is None:
        if provides is None or permission is None:
            raise ValueError('Required arguments: '
                                'checker or both provides and permissions')
        if permission == PublicPermission:
            permission = CheckerPublic
        checker = InterfaceChecker(provides, permission)
    ob = PermissionProxy(ob)
    ob.__Security_checker__ = checker
    return ob

def protectedFactory(original_factory, provides, permission):
    if permission == PublicPermission:
        permission = CheckerPublic
    checker = InterfaceChecker(provides, permission)
    # This has to be named 'factory', aparently, so as not to confuse apidoc :(
    def factory(*args):
        ob = original_factory(*args)
        try:
            ob.__Security_checker__ = checker
        except AttributeError:
            ob = Proxy(ob, checker)
        return ob
    factory.factory = original_factory
    return factory

def securityAdapterFactory(factory, permission, locate, trusted):
    if permission == PublicPermission:
        permission = CheckerPublic
    if locate or (permission is not None and permission is not CheckerPublic):
        if trusted:
            return LocatingTrustedAdapterFactory(factory)
        else:
            return LocatingUntrustedAdapterFactory(factory)
    elif trusted:
        return TrustedAdapterFactory(factory)
    else:
        return factory
