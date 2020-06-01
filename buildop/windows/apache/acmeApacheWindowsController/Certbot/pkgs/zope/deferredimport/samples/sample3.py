

import zope.deferredimport
import zope.deferredimport.sample4

zope.deferredimport.define(
    sample1 = 'zope.deferredimport.sample1',
    one = 'zope.deferredimport.sample1:x',
    two = 'zope.deferredimport.sample1:C.y',
    )

x = 1

