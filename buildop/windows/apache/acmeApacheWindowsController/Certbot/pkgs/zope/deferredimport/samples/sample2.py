

import zope.deferredimport

zope.deferredimport.define(
    sample1 = 'zope.deferredimport.sample1',
    one = 'zope.deferredimport.sample1:x',
    two = 'zope.deferredimport.sample1:C.y',
    )

three = 3
x = 4
def getx():
    return x

