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

import sys
import types

if sys.version_info[0] < 3: #pragma NO COVER

    import cPickle as _pickle

    CLASS_TYPES = (type, types.ClassType)

    PYTHON3 = False
    PYTHON2 = True

else: #pragma NO COVER

    import pickle as _pickle

    CLASS_TYPES = (type,)

    PYTHON3 = True
    PYTHON2 = False
