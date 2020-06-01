##############################################################################
#
# Copyright (c) 2006 Zope Foundation and Contributors.
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
"""Basic components support
"""

from zope.component._api import handle
from zope.component._declaration import adapter

from zope.interface.interfaces import IAdapterRegistration
from zope.interface.interfaces import IHandlerRegistration
from zope.interface.interfaces import IRegistrationEvent
from zope.interface.interfaces import ISubscriptionAdapterRegistration
from zope.interface.interfaces import IUtilityRegistration

# BBB, import component-related from zope.interface
import zope.deferredimport
zope.deferredimport.deprecatedFrom(
    "Import from zope.interface.registry",
    "zope.interface.registry",
    'Components',
    '_getUtilityProvided',
    '_getAdapterProvided',
    '_getAdapterRequired',
    'UtilityRegistration',
    'AdapterRegistration',
    'SubscriptionRegistration',
    'HandlerRegistration',
)


@adapter(IUtilityRegistration, IRegistrationEvent)
def dispatchUtilityRegistrationEvent(registration, event):
    handle(registration.component, event)

@adapter(IAdapterRegistration, IRegistrationEvent)
def dispatchAdapterRegistrationEvent(registration, event):
    handle(registration.factory, event)

@adapter(ISubscriptionAdapterRegistration, IRegistrationEvent)
def dispatchSubscriptionAdapterRegistrationEvent(registration, event):
    handle(registration.factory, event)

@adapter(IHandlerRegistration, IRegistrationEvent)
def dispatchHandlerRegistrationEvent(registration, event):
    handle(registration.handler, event)
