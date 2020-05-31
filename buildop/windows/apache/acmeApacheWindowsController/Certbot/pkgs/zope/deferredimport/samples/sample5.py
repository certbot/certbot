

import zope.deferredimport
zope.deferredimport.initialize()

import zope.deferredimport.sample6

zope.deferredimport.define(
    sample1 = 'zope.deferredimport.sample1',
    one = 'zope.deferredimport.sample1:x',
    two = 'zope.deferredimport.sample1:C.y',
    )

x = 1

