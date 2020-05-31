# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from .base import *  # noqa

# don't use an unicode string
localeID = 'en_AU'
dateSep = ['-', '/']
uses24 = False

dateFormats = {
    'full': 'EEEE, d MMMM yyyy',
    'long': 'd MMMM yyyy',
    'medium': 'dd/MM/yyyy',
    'short': 'd/MM/yy',
}

timeFormats['long'] = timeFormats['full']

dp_order = ['d', 'm', 'y']
