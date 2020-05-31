##############################################################################
#
# Copyright (c) 2004 Zope Foundation and Contributors.
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
"""Component Architecture-specific event dispatching

Based on subscription adapters / handlers.
"""

from zope.event import subscribers as event_subscribers

from zope.interface.interfaces import IObjectEvent
from zope.component._api import subscribers as component_subscribers
from zope.component._declaration import adapter


def dispatch(*event):
    component_subscribers(event, None)

event_subscribers.append(dispatch)


@adapter(IObjectEvent)
def objectEventNotify(event):
    """Dispatch ObjectEvents to interested adapters.
    """
    component_subscribers((event.object, event), None)
