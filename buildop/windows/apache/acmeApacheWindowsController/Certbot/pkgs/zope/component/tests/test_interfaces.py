##############################################################################
#
# Copyright (c) 2017 Zope Foundation and Contributors.
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
"""
Tests for zope.component.interfaces
"""

import unittest

class TestBackwardsCompat(unittest.TestCase):

    def test_interface_warnings(self):
        from zope.component import interfaces
        import warnings
        for name in (
                'ComponentLookupError',
                'Invalid',
                'IObjectEvent',
                'ObjectEvent',
                'IComponentLookup',
                'IRegistration',
                'IUtilityRegistration',
                '_IBaseAdapterRegistration',
                'IAdapterRegistration',
                'ISubscriptionAdapterRegistration',
                'IHandlerRegistration',
                'IRegistrationEvent',
                'RegistrationEvent',
                'IRegistered',
                'Registered',
                'IUnregistered',
                'Unregistered',
                'IComponentRegistry',
                'IComponents',
        ):
            with warnings.catch_warnings(record=True) as log:
                warnings.simplefilter("always")
                getattr(interfaces, name)

                self.assertEqual(1, len(log), name)
                message = str(log[0].message)
                self.assertIn(name, message)
                self.assertIn("Import from zope.interface.interfaces", message)
