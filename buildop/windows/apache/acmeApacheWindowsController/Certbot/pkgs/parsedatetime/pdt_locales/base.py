from __future__ import unicode_literals

locale_keys = set([
    'MonthOffsets', 'Months', 'WeekdayOffsets', 'Weekdays',
    'dateFormats', 'dateSep', 'dayOffsets', 'dp_order',
    'localeID', 'meridian', 'Modifiers', 're_sources', 're_values',
    'shortMonths', 'shortWeekdays', 'timeFormats', 'timeSep', 'units',
    'uses24', 'usesMeridian', 'numbers', 'decimal_mark', 'small',
    'magnitude', 'ignore'])

localeID = None

dateSep = ['/', '.']
timeSep = [':']
meridian = ['AM', 'PM']
usesMeridian = True
uses24 = True
WeekdayOffsets = {}
MonthOffsets = {}

# always lowercase any lookup values - helper code expects that
Weekdays = [
    'monday', 'tuesday', 'wednesday', 'thursday',
    'friday', 'saturday', 'sunday',
]

shortWeekdays = [
    'mon', 'tues|tue', 'wed', 'thu', 'fri', 'sat', 'sun',
]

Months = [
    'january', 'february', 'march', 'april', 'may', 'june', 'july',
    'august', 'september', 'october', 'november', 'december',
]

shortMonths = [
    'jan', 'feb', 'mar', 'apr', 'may', 'jun',
    'jul', 'aug', 'sep', 'oct', 'nov', 'dec',
]

# use the same formats as ICU by default
dateFormats = {
    'full': 'EEEE, MMMM d, yyyy',
    'long': 'MMMM d, yyyy',
    'medium': 'MMM d, yyyy',
    'short': 'M/d/yy'
}

timeFormats = {
    'full': 'h:mm:ss a z',
    'long': 'h:mm:ss a z',
    'medium': 'h:mm:ss a',
    'short': 'h:mm a',
}

dp_order = ['m', 'd', 'y']

# Used to parse expressions like "in 5 hours"
numbers = {
    'zero': 0,
    'one': 1,
    'a': 1,
    'an': 1,
    'two': 2,
    'three': 3,
    'four': 4,
    'five': 5,
    'six': 6,
    'seven': 7,
    'eight': 8,
    'nine': 9,
    'ten': 10,
    'eleven': 11,
    'thirteen': 13,
    'fourteen': 14,
    'fifteen': 15,
    'sixteen': 16,
    'seventeen': 17,
    'eighteen': 18,
    'nineteen': 19,
    'twenty': 20,
}

decimal_mark = '.'


# this will be added to re_values later
units = {
    'seconds': ['second', 'seconds', 'sec', 's'],
    'minutes': ['minute', 'minutes', 'min', 'm'],
    'hours': ['hour', 'hours', 'hr', 'h'],
    'days': ['day', 'days', 'dy', 'd'],
    'weeks': ['week', 'weeks', 'wk', 'w'],
    'months': ['month', 'months', 'mth'],
    'years': ['year', 'years', 'yr', 'y'],
}


# text constants to be used by later regular expressions
re_values = {
    'specials': 'in|on|of|at',
    'timeseparator': ':',
    'rangeseparator': '-',
    'daysuffix': 'rd|st|nd|th',
    'meridian': r'am|pm|a\.m\.|p\.m\.|a|p',
    'qunits': 'h|m|s|d|w|y',
    'now': ['now', 'right now'],
}

# Used to adjust the returned date before/after the source
Modifiers = {
    'from': 1,
    'before': -1,
    'after': 1,
    'ago': -1,
    'prior': -1,
    'prev': -1,
    'last': -1,
    'next': 1,
    'previous': -1,
    'end of': 0,
    'this': 0,
    'eod': 1,
    'eom': 1,
    'eoy': 1,
}

dayOffsets = {
    'tomorrow': 1,
    'today': 0,
    'yesterday': -1,
}

# special day and/or times, i.e. lunch, noon, evening
# each element in the dictionary is a dictionary that is used
# to fill in any value to be replace - the current date/time will
# already have been populated by the method buildSources
re_sources = {
    'noon': {'hr': 12, 'mn': 0, 'sec': 0},
    'afternoon': {'hr': 13, 'mn': 0, 'sec': 0},
    'lunch': {'hr': 12, 'mn': 0, 'sec': 0},
    'morning': {'hr': 6, 'mn': 0, 'sec': 0},
    'breakfast': {'hr': 8, 'mn': 0, 'sec': 0},
    'dinner': {'hr': 19, 'mn': 0, 'sec': 0},
    'evening': {'hr': 18, 'mn': 0, 'sec': 0},
    'midnight': {'hr': 0, 'mn': 0, 'sec': 0},
    'night': {'hr': 21, 'mn': 0, 'sec': 0},
    'tonight': {'hr': 21, 'mn': 0, 'sec': 0},
    'eod': {'hr': 17, 'mn': 0, 'sec': 0},
}

small = {
    'zero': 0,
    'one': 1,
    'a': 1,
    'an': 1,
    'two': 2,
    'three': 3,
    'four': 4,
    'five': 5,
    'six': 6,
    'seven': 7,
    'eight': 8,
    'nine': 9,
    'ten': 10,
    'eleven': 11,
    'twelve': 12,
    'thirteen': 13,
    'fourteen': 14,
    'fifteen': 15,
    'sixteen': 16,
    'seventeen': 17,
    'eighteen': 18,
    'nineteen': 19,
    'twenty': 20,
    'thirty': 30,
    'forty': 40,
    'fifty': 50,
    'sixty': 60,
    'seventy': 70,
    'eighty': 80,
    'ninety': 90
}

magnitude = {
    'thousand': 1000,
    'million': 1000000,
    'billion': 1000000000,
    'trillion': 1000000000000,
    'quadrillion': 1000000000000000,
    'quintillion': 1000000000000000000,
    'sextillion': 1000000000000000000000,
    'septillion': 1000000000000000000000000,
    'octillion': 1000000000000000000000000000,
    'nonillion': 1000000000000000000000000000000,
    'decillion': 1000000000000000000000000000000000,
}

ignore = ('and', ',')
