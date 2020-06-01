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
"""Zope 3 Component Architecture
"""
from zope.interface import Interface
from zope.interface import implementedBy
from zope.interface import moduleProvides
from zope.interface import named
from zope.interface import providedBy

from zope.interface.interfaces import ComponentLookupError
from zope.component.interfaces import IComponentArchitecture
from zope.interface.interfaces import IComponentLookup
from zope.component.interfaces import IComponentRegistrationConvenience
from zope.component.interfaces import IFactory

from zope.component.globalregistry import getGlobalSiteManager
from zope.component.globalregistry import globalSiteManager
from zope.component.globalregistry import provideAdapter
from zope.component.globalregistry import provideHandler
from zope.component.globalregistry import provideSubscriptionAdapter
from zope.component.globalregistry import provideUtility

from zope.component._api import adapter_hook
from zope.component._api import createObject
from zope.component._api import getAdapter
from zope.component._api import getAdapterInContext
from zope.component._api import getAdapters
from zope.component._api import getAllUtilitiesRegisteredFor
from zope.component._api import getFactoriesFor
from zope.component._api import getFactoryInterfaces
from zope.component._api import getMultiAdapter
from zope.component._api import getSiteManager
from zope.component._api import getUtilitiesFor
from zope.component._api import getUtility
from zope.component._api import getNextUtility
from zope.component._api import handle
from zope.component._api import queryAdapter
from zope.component._api import queryAdapterInContext
from zope.component._api import queryMultiAdapter
from zope.component._api import queryUtility
from zope.component._api import queryNextUtility
from zope.component._api import subscribers

from zope.component._declaration import adaptedBy
from zope.component._declaration import adapter
from zope.component._declaration import adapts

moduleProvides(IComponentArchitecture, IComponentRegistrationConvenience)
__all__ = tuple(IComponentArchitecture)
