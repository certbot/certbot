# -*- coding: utf-8 -*-
"""
parsedatetime/warns.py

All subclasses inherited from `Warning` class

"""
from __future__ import absolute_import

import warnings


class pdtDeprecationWarning(DeprecationWarning):
    pass


class pdtPendingDeprecationWarning(PendingDeprecationWarning):
    pass


class pdt20DeprecationWarning(pdtPendingDeprecationWarning):
    pass


warnings.simplefilter('default', pdtDeprecationWarning)
warnings.simplefilter('ignore', pdtPendingDeprecationWarning)
