##############################################################################
#
# Copyright (c) 2010 Zope Foundation and Contributors.
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

import os

from zope.configuration import xmlconfig, config
try:
    from zope.testing.cleanup import cleanUp
except ImportError: # pragma: no cover
    def cleanUp():
        pass

from zope.component import provideHandler
from zope.component.hooks import setHooks
from zope.component.eventtesting import events, clearEvents


class LayerBase(object):
    """Sane layer base class.

    zope.testing implements an advanced mechanism so that layer setUp,
    tearDown, testSetUp and testTearDown code gets called in the right
    order. These methods are supposed to be @classmethods and should
    not use super() as the test runner is supposed to take care of that.

    In practice, this mechanism turns out not to be useful and
    overcomplicated.  It becomes difficult to pass information into
    layers (such as a ZCML file to load), because the only way to pass
    in information is to subclass, and subclassing these layers leads
    to a range of interactions that is hard to reason about.

    We'd rather just use Python and the super mechanism, as we know how
    to reason about that. This base class is a hack to make this
    possible.

    The hack requires us to set __bases__, __module__ and
    __name__. This fools zope.testing into thinking that this layer
    instance is a class it can work with.

    It'd be better if zope.testing just called a minimal API and
    didn't try to be fancy. Fancy layer inheritance mechanisms can
    then be implemented elsewhere if people want to. But unfortunately
    it does implement a fancy mechanism and we need to fool it.
    """

    __bases__ = ()

    def __init__(self, package, name=None):
        if name is None:
            name = self.__class__.__name__
        self.__name__ = name
        self.__module__ = package.__name__
        self.package = package

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def testSetUp(self):
        pass

    def testTearDown(self):
        pass

class ZCMLLayerBase(LayerBase):
    """Base class to load up some ZCML.
    """
    def __init__(self, package, name=None, features=None):
        super(ZCMLLayerBase, self).__init__(package, name)
        self.features = features or []

    def setUp(self):
        setHooks()
        context = config.ConfigurationMachine()
        xmlconfig.registerCommonDirectives(context)
        for feature in self.features:
            context.provideFeature(feature)
        self.context = self._load_zcml(context)
        provideHandler(events.append, (None,))

    def testTearDown(self):
        clearEvents()

    def tearDown(self):
        cleanUp()

    def _load_zcml(self, context):
        raise NotImplementedError

class ZCMLFileLayer(ZCMLLayerBase):
    """This layer can be used to run tests with a ZCML file loaded.

    The ZCML file is assumed to include sufficient (meta)configuration
    so that it can be interpreted itself. I.e. to create a ZCMLLayer
    based on another ZCMLLayer's ZCML, just use a ZCML include
    statement in your own ZCML to load it.
    """
    def __init__(self, package, zcml_file='ftesting.zcml',
                 name=None, features=None):
        super(ZCMLFileLayer, self).__init__(package, name, features)
        self.zcml_file = os.path.join(os.path.dirname(package.__file__),
                                      zcml_file)

    def _load_zcml(self, context):
        return xmlconfig.file(self.zcml_file,
                              package=self.package,
                              context=context, execute=True)
