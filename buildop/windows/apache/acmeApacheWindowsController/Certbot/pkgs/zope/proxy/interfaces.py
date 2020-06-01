##############################################################################
#
# Copyright (c) 2001, 2002 Zope Foundation and Contributors.
# All Rights Reserved.
#
# This software is subject to the provisions of the Zope Public License,
# Version 2.1 (ZPL).  A copy of the ZPL should accompany this distribution.
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL EXPRESS OR IMPLIED
# WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND FITNESS
# FOR A PARTICULAR PURPOSE
#
##############################################################################
"""Proxy-related interfaces.
"""

from zope.interface import Interface

class IProxyIntrospection(Interface):
    """Provides methods for indentifying proxies and extracting proxied objects
    """

    def isProxy(obj, proxytype=None):
        """Check whether the given object is a proxy

        If proxytype is not None, checkes whether the object is
        proxied by the given proxytype.
        """

    def sameProxiedObjects(ob1, ob2):
        """Check whether ob1 and ob2 are the same or proxies of the same object
        """

    def getProxiedObject(obj):
        """Get the proxied Object

        If the object isn't proxied, then just return the object.
        """

    def setProxiedObject(ob1, ob2):
        """Set the underlying object for ob1 to ob2, returning the old object.

        Raises TypeError if ob1 is not a proxy.
        """

    def removeAllProxies(obj):
        """Get the proxied object with no proxies

        If obj is not a proxied object, return obj.

        The returned object has no proxies.
        """

    def queryProxy(obj, proxytype, default=None):
        """Look for a proxy of the given type around the object

        If no such proxy can be found, return the default.
        """

    def queryInnerProxy(obj, proxytype, default=None):
        """Look for the inner-most proxy of the given type around the object

        If no such proxy can be found, return the default.

        If there is such a proxy, return the inner-most one.
        """
