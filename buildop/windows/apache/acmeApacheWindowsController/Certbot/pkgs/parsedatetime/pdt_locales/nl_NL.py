# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from .base import *  # noqa

# don't use an unicode string
localeID = 'nl_NL'
dateSep = ['-', '/']
timeSep = [':']
meridian = []
usesMeridian = False
uses24 = True
decimal_mark = ','

Weekdays = [
    'maandag', 'dinsdag', 'woensdag', 'donderdag',
    'vrijdag', 'zaterdag', 'zondag',
]
shortWeekdays = [
    'ma', 'di', 'wo', 'do', 'vr', 'za', 'zo',
]
Months = [
    'januari', 'februari', 'maart', 'april', 'mei', 'juni', 'juli',
    'augustus', 'september', 'oktober', 'november', 'december',
]
shortMonths = [
    'jan', 'feb', 'mar', 'apr', 'mei', 'jun',
    'jul', 'aug', 'sep', 'okt', 'nov', 'dec',
]
dateFormats = {
    'full': 'EEEE, dd MMMM yyyy',
    'long': 'dd MMMM yyyy',
    'medium': 'dd-MM-yyyy',
    'short': 'dd-MM-yy',
}

timeFormats = {
    'full': 'HH:mm:ss v',
    'long': 'HH:mm:ss z',
    'medium': 'HH:mm:ss',
    'short': 'HH:mm',
}

dp_order = ['d', 'm', 'y']

# the short version would be a capital M,
# as I understand it we can't distinguish
# between m for minutes and M for months.
units = {
    'seconds': ['secunden', 'sec', 's'],
    'minutes': ['minuten', 'min', 'm'],
    'hours': ['uren', 'uur', 'h'],
    'days': ['dagen', 'dag', 'd'],
    'weeks': ['weken', 'w'],
    'months': ['maanden', 'maand'],
    'years': ['jaar', 'jaren', 'j'],
}

re_values = re_values.copy()
re_values.update({
    'specials': 'om',
    'timeseparator': ':',
    'rangeseparator': '-',
    'daysuffix': ' |de',
    'qunits': 'h|m|s|d|w|m|j',
    'now': ['nu'],
})

# Used to adjust the returned date before/after the source
# still looking for insight on how to translate all of them to german.
Modifiers = {
    'vanaf': 1,
    'voor': -1,
    'na': 1,
    'vorige': -1,
    'eervorige': -1,
    'prev': -1,
    'laastste': -1,
    'volgende': 1,
    'deze': 0,
    'vorige': -1,
    'over': 2,
    'eind van': 0,
}

# morgen/abermorgen does not work, see
# http://code.google.com/p/parsedatetime/issues/detail?id=19
dayOffsets = {
    'morgen': 1,
    'vandaag': 0,
    'gisteren': -1,
    'eergisteren': -2,
    'overmorgen': 2,
}

# special day and/or times, i.e. lunch, noon, evening
# each element in the dictionary is a dictionary that is used
# to fill in any value to be replace - the current date/time will
# already have been populated by the method buildSources
re_sources = {
    'middag': {'hr': 12, 'mn': 0, 'sec': 0},
    'vanmiddag': {'hr': 12, 'mn': 0, 'sec': 0},
    'lunch': {'hr': 12, 'mn': 0, 'sec': 0},
    'morgen': {'hr': 6, 'mn': 0, 'sec': 0},
    "'s morgens": {'hr': 6, 'mn': 0, 'sec': 0},
    'ontbijt': {'hr': 8, 'mn': 0, 'sec': 0},
    'avondeten': {'hr': 19, 'mn': 0, 'sec': 0},
    'avond': {'hr': 18, 'mn': 0, 'sec': 0},
    'avonds': {'hr': 18, 'mn': 0, 'sec': 0},
    'middernacht': {'hr': 0, 'mn': 0, 'sec': 0},
    'nacht': {'hr': 21, 'mn': 0, 'sec': 0},
    'nachts': {'hr': 21, 'mn': 0, 'sec': 0},
    'vanavond': {'hr': 21, 'mn': 0, 'sec': 0},
    'vannacht': {'hr': 21, 'mn': 0, 'sec': 0},
}
