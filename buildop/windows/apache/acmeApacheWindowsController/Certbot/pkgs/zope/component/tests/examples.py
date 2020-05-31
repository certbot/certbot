##############################################################################
#
# Copyright (c) 2001, 2002, 2009 Zope Foundation and Contributors.
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
"""Examples supporting Sphinx doctest snippets.
"""
import sys

from zope.interface import Interface
from zope.interface import implementer
from zope.interface.interfaces import IInterface

from zope.component._declaration import adapter
from zope.component.testfiles.views import IC

def write(x):
    sys.stdout.write('%s\n' % x)

class ITestType(IInterface):
    pass


class I1(Interface):
    pass

class I2(Interface):
    pass

class I3(Interface):
    pass

class I4(Interface):
    pass

class IGI(Interface):
    pass

class IQI(Interface):
    pass

class ISI(Interface):
    pass

class ISII(Interface):
    pass

class U(object):

    def __init__(self, name):
        self.__name__ = name

    def __repr__(self):
        return "%s(%s)" % (self.__class__.__name__, self.__name__)

@implementer(I1)
class U1(U):
    pass

@implementer(I1, I2)
class U12(U):
    pass

@adapter(I1)
def handle1(x):
    write('handle1 %s' % x)

def handle2(*objects):
    write( 'handle2 ' + repr(objects))

@adapter(I1)
def handle3(x):
    write( 'handle3 %s' % x)

@adapter(I1)
def handle4(x):
    write( 'handle4 %s' % x)

class GlobalRegistry:
    pass

from zope.component.globalregistry import GlobalAdapterRegistry
base = GlobalAdapterRegistry(GlobalRegistry, 'adapters')
GlobalRegistry.adapters = base
def clear_base():
    base.__init__(GlobalRegistry, 'adapters')


@implementer(I1)
class Ob(object):
    def __repr__(self):
        return '<instance Ob>'


ob = Ob()

@implementer(I2)
class Ob2(object):
    def __repr__(self):
        return '<instance Ob2>'

@implementer(IC)
class Ob3(object):
    pass

@implementer(I2)
class Comp(object):
    def __init__(self, context):
        self.context = context

comp = Comp(1)


class ConformsToIComponentLookup(object):
    """Allow a dummy sitemanager to conform/adapt to `IComponentLookup`."""

    def __init__(self, sitemanager):
        self.sitemanager = sitemanager

    def __conform__(self, interface):
        """This method is specified by the adapter PEP to do the adaptation."""
        from zope.interface.interfaces import IComponentLookup
        if interface is IComponentLookup:
            return self.sitemanager


def clearZCML(test=None):
    from zope.configuration.xmlconfig import XMLConfig
    import zope.component
    from zope.component.testing import setUp
    from zope.component.testing import tearDown
    tearDown()
    setUp()
    XMLConfig('meta.zcml', zope.component)()
