

import zope.deferredimport

zope.deferredimport.deprecatedFrom(
    "Import from sample1 instead",
    'zope.deferredimport.sample1',
    'x', 'z', 'q',
    )

zope.deferredimport.defineFrom(
    'zope.deferredimport.sample9',
    'a', 'b', 'c',
    )

