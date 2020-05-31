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
"""Placeless Test Setup
"""

from zope.component import provideHandler
from zope.component.event import objectEventNotify
from zope.component.registry import dispatchUtilityRegistrationEvent
from zope.component.registry import dispatchAdapterRegistrationEvent
from zope.component.registry import (
    dispatchSubscriptionAdapterRegistrationEvent)
from zope.component.registry import dispatchHandlerRegistrationEvent
try:
    from zope.testing.cleanup import addCleanUp
except ImportError:
    def addCleanUp(x):
        pass

events = []
def getEvents(event_type=None, filter=None):
    r = []
    for event in events:
        if event_type is not None and not event_type.providedBy(event):
            continue
        if filter is not None and not filter(event):
            continue
        r.append(event)

    return r

def clearEvents():
    del events[:]
addCleanUp(clearEvents)

class PlacelessSetup:

    def setUp(self):
        provideHandler(objectEventNotify)
        provideHandler(dispatchUtilityRegistrationEvent)
        provideHandler(dispatchAdapterRegistrationEvent)
        provideHandler(dispatchSubscriptionAdapterRegistrationEvent)
        provideHandler(dispatchHandlerRegistrationEvent)
        provideHandler(events.append, (None,))

def setUp(test=None):
    PlacelessSetup().setUp()
