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
# FOR A PARTICULAR PURPOSE.
#
##############################################################################
"""Hooks for getting and setting a site in the thread global namespace.
"""
__docformat__ = 'restructuredtext'

import contextlib
import threading

try:
    from zope.security.proxy import removeSecurityProxy
except ImportError: #pragma NO COVER
    def removeSecurityProxy(x):
        return x

from zope.component.globalregistry import getGlobalSiteManager
from zope.interface.interfaces import ComponentLookupError
from zope.interface.interfaces import IComponentLookup


class read_property(object):
    """Descriptor for property-like computed attributes.

    Unlike the standard 'property', this descriptor allows assigning a
    value to the instance, shadowing the property getter function.
    """
    def __init__(self, func):
        self.func = func

    def __get__(self, inst, cls):
        if inst is None:
            return self

        return self.func(inst)

class SiteInfo(threading.local):
    site = None
    sm = getGlobalSiteManager()

    @read_property
    def adapter_hook(self):
        adapter_hook = self.sm.adapters.adapter_hook
        self.adapter_hook = adapter_hook
        return adapter_hook

siteinfo = SiteInfo()

def setSite(site=None):
    if site is None:
        sm = getGlobalSiteManager()
    else:

        # We remove the security proxy because there's no way for
        # untrusted code to get at it without it being proxied again.

        # We should really look look at this again though, especially
        # once site managers do less.  There's probably no good reason why
        # they can't be proxied.  Well, except maybe for performance.

        site = removeSecurityProxy(site)
        # The getSiteManager method is defined by IPossibleSite.
        sm = site.getSiteManager()

    siteinfo.site = site
    siteinfo.sm = sm
    try:
        del siteinfo.adapter_hook
    except AttributeError:
        pass

def getSite():
    return siteinfo.site


@contextlib.contextmanager
def site(site):
    old_site = getSite()
    setSite(site)
    try:
        yield
    finally:
        setSite(old_site)


def getSiteManager(context=None):
    """A special hook for getting the site manager.

    Here we take the currently set site into account to find the appropriate
    site manager.
    """
    if context is None:
        return siteinfo.sm

    # We remove the security proxy because there's no way for
    # untrusted code to get at it without it being proxied again.

    # We should really look look at this again though, especially
    # once site managers do less.  There's probably no good reason why
    # they can't be proxied.  Well, except maybe for performance.
    sm = IComponentLookup(
        context, getGlobalSiteManager())
    sm = removeSecurityProxy(sm)
    return sm


def adapter_hook(interface, object, name='', default=None):
    try:
        return siteinfo.adapter_hook(interface, object, name, default)
    except ComponentLookupError:
        return default


def setHooks():
    from zope.component import _api
    _api.adapter_hook.sethook(adapter_hook)
    _api.getSiteManager.sethook(getSiteManager)

def resetHooks():
    # Reset hookable functions to original implementation.
    from zope.component import _api
    _api.adapter_hook.reset()
    _api.getSiteManager.reset()
    # be sure the old adapter hook isn't cached, since
    # it is derived from the SiteManager
    try:
        del siteinfo.adapter_hook
    except AttributeError:
        pass

# Clear the site thread global
clearSite = setSite
try:
    from zope.testing.cleanup import addCleanUp
except ImportError: #pragma NO COVER
    pass
else:
    addCleanUp(resetHooks)
