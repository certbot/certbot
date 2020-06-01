

import zope.deferredimport
zope.deferredimport.initialize()

zope.deferredimport.deprecated(
    "Import from sample1 instead",
    x = 'zope.deferredimport.sample1:x',
    y = 'zope.deferredimport.sample1:C.y',
    z = 'zope.deferredimport.sample1:z',
    )

