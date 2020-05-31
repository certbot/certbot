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
"""Persistent component managers
"""
from persistent import Persistent
from persistent.mapping import PersistentMapping
from persistent.list import PersistentList
from zope.interface.adapter import VerifyingAdapterRegistry
from zope.interface.registry import Components

class PersistentAdapterRegistry(VerifyingAdapterRegistry, Persistent):

    def changed(self, originally_changed):
        if originally_changed is self:
            self._p_changed = True
        super(PersistentAdapterRegistry, self).changed(originally_changed)

    def __getstate__(self):
        state = super(PersistentAdapterRegistry, self).__getstate__().copy()
        for name in self._delegated:
            state.pop(name, 0)
        state.pop('ro', None)
        return state

    def __setstate__(self, state):
        bases = state.pop('__bases__', ())
        super(PersistentAdapterRegistry, self).__setstate__(state)
        self._createLookup()
        self.__bases__ = bases
        self._v_lookup.changed(self)
        
        
class PersistentComponents(Components):

    def _init_registries(self):
        self.adapters = PersistentAdapterRegistry()
        self.utilities = PersistentAdapterRegistry()

    def _init_registrations(self):
        self._utility_registrations = PersistentMapping()
        self._adapter_registrations = PersistentMapping()
        self._subscription_registrations = PersistentList()
        self._handler_registrations = PersistentList()
