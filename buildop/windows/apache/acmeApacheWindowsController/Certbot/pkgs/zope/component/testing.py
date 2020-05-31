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

# HACK to make sure basicmost event subscriber is installed
import zope.component.event

# we really don't need special setup now:
class _PlacelessSetupFallback(object):
    def cleanUp(self):
        from zope.component.globalregistry import base
        base.__init__('base')

    setUp = tearDown = cleanUp

try:
    from zope.testing.cleanup import CleanUp as PlacelessSetup
except ImportError: # pragma: no cover
    PlacelessSetup = _PlacelessSetupFallback

def setUp(test=None):
    PlacelessSetup().setUp()

def tearDown(test=None):
    PlacelessSetup().tearDown()
