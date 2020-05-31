# -*- encoding: utf-8 -*-

"""
pdt_locales

All of the included locale classes shipped with pdt.
"""
import datetime

try:
    range = xrange
except NameError:
    pass

try:
    import PyICU as pyicu
except ImportError:
    pyicu = None


def icu_object(mapping):
    return type('_icu', (object,), mapping)


def merge_weekdays(base_wd, icu_wd):
    result = []
    for left, right in zip(base_wd, icu_wd):
        if left == right:
            result.append(left)
            continue
        left = set(left.split('|'))
        right = set(right.split('|'))
        result.append('|'.join(left | right))
    return result


def get_icu(locale):
    from . import base
    result = dict([(key, getattr(base, key))
                   for key in dir(base) if not key.startswith('_')])
    result['icu'] = None

    if pyicu is None:
        return icu_object(result)

    if locale is None:
        locale = 'en_US'
    result['icu'] = icu = pyicu.Locale(locale)

    if icu is None:
        return icu_object(result)

    # grab spelled out format of all numbers from 0 to 100
    rbnf = pyicu.RuleBasedNumberFormat(pyicu.URBNFRuleSetTag.SPELLOUT, icu)
    result['numbers'].update([(rbnf.format(i), i) for i in range(0, 100)])

    symbols = result['symbols'] = pyicu.DateFormatSymbols(icu)

    # grab ICU list of weekdays, skipping first entry which
    # is always blank
    wd = [w.lower() for w in symbols.getWeekdays()[1:]]
    swd = [sw.lower() for sw in symbols.getShortWeekdays()[1:]]

    # store them in our list with Monday first (ICU puts Sunday first)
    result['Weekdays'] = merge_weekdays(result['Weekdays'],
                                        wd[1:] + wd[0:1])
    result['shortWeekdays'] = merge_weekdays(result['shortWeekdays'],
                                             swd[1:] + swd[0:1])
    result['Months'] = [m.lower() for m in symbols.getMonths()]
    result['shortMonths'] = [sm.lower() for sm in symbols.getShortMonths()]
    keys = ['full', 'long', 'medium', 'short']

    createDateInstance = pyicu.DateFormat.createDateInstance
    createTimeInstance = pyicu.DateFormat.createTimeInstance
    icu_df = result['icu_df'] = {
        'full': createDateInstance(pyicu.DateFormat.kFull, icu),
        'long': createDateInstance(pyicu.DateFormat.kLong, icu),
        'medium': createDateInstance(pyicu.DateFormat.kMedium, icu),
        'short': createDateInstance(pyicu.DateFormat.kShort, icu),
    }
    icu_tf = result['icu_tf'] = {
        'full': createTimeInstance(pyicu.DateFormat.kFull, icu),
        'long': createTimeInstance(pyicu.DateFormat.kLong, icu),
        'medium': createTimeInstance(pyicu.DateFormat.kMedium, icu),
        'short': createTimeInstance(pyicu.DateFormat.kShort, icu),
    }

    result['dateFormats'] = {}
    result['timeFormats'] = {}
    for x in keys:
        result['dateFormats'][x] = icu_df[x].toPattern()
        result['timeFormats'][x] = icu_tf[x].toPattern()

    am = pm = ts = ''

    # ICU doesn't seem to provide directly the date or time separator
    # so we have to figure it out
    o = result['icu_tf']['short']
    s = result['timeFormats']['short']

    result['usesMeridian'] = 'a' in s
    result['uses24'] = 'H' in s

    # '11:45 AM' or '11:45'
    s = o.format(datetime.datetime(2003, 10, 30, 11, 45))

    # ': AM' or ':'
    s = s.replace('11', '').replace('45', '')

    if len(s) > 0:
        ts = s[0]

    if result['usesMeridian']:
        # '23:45 AM' or '23:45'
        am = s[1:].strip()
        s = o.format(datetime.datetime(2003, 10, 30, 23, 45))

        if result['uses24']:
            s = s.replace('23', '')
        else:
            s = s.replace('11', '')

            # 'PM' or ''
        pm = s.replace('45', '').replace(ts, '').strip()

    result['timeSep'] = [ts]
    result['meridian'] = [am, pm] if am and pm else []

    o = result['icu_df']['short']
    s = o.format(datetime.datetime(2003, 10, 30, 11, 45))
    s = s.replace('10', '').replace('30', '').replace(
        '03', '').replace('2003', '')

    if len(s) > 0:
        ds = s[0]
    else:
        ds = '/'

    result['dateSep'] = [ds]
    s = result['dateFormats']['short']
    l = s.lower().split(ds)
    dp_order = []

    for s in l:
        if len(s) > 0:
            dp_order.append(s[:1])

    result['dp_order'] = dp_order
    return icu_object(result)
