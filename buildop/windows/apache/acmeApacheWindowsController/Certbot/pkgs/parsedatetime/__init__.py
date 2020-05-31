# -*- coding: utf-8 -*-
#
# vim: sw=2 ts=2 sts=2
#
# Copyright 2004-2016 Mike Taylor
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""parsedatetime

Parse human-readable date/time text.

Requires Python 2.6 or later
"""

from __future__ import with_statement, absolute_import, unicode_literals

import re
import time
import logging
import warnings
import datetime
import calendar
import contextlib
import email.utils

from .pdt_locales import (locales as _locales,
                          get_icu, load_locale)
from .context import pdtContext, pdtContextStack
from .warns import pdt20DeprecationWarning


__author__ = 'Mike Taylor'
__email__ = 'bear@bear.im'
__copyright__ = 'Copyright (c) 2017 Mike Taylor'
__license__ = 'Apache License 2.0'
__version__ = '2.4'
__url__ = 'https://github.com/bear/parsedatetime'
__download_url__ = 'https://pypi.python.org/pypi/parsedatetime'
__description__ = 'Parse human-readable date/time text.'

# as a library, do *not* setup logging
# see docs.python.org/2/howto/logging.html#configuring-logging-for-a-library
# Set default logging handler to avoid "No handler found" warnings.

try:  # Python 2.7+
    from logging import NullHandler
except ImportError:
    class NullHandler(logging.Handler):

        def emit(self, record):
            pass

log = logging.getLogger(__name__)
log.addHandler(NullHandler())

debug = False

pdtLocales = dict([(x, load_locale(x)) for x in _locales])


# Copied from feedparser.py
# Universal Feedparser
# Copyright (c) 2002-2006, Mark Pilgrim, All rights reserved.
# Originally a def inside of _parse_date_w3dtf()
def _extract_date(m):
    year = int(m.group('year'))
    if year < 100:
        year = 100 * int(time.gmtime()[0] / 100) + int(year)
    if year < 1000:
        return 0, 0, 0
    julian = m.group('julian')
    if julian:
        julian = int(julian)
        month = julian / 30 + 1
        day = julian % 30 + 1
        jday = None
        while jday != julian:
            t = time.mktime((year, month, day, 0, 0, 0, 0, 0, 0))
            jday = time.gmtime(t)[-2]
            diff = abs(jday - julian)
            if jday > julian:
                if diff < day:
                    day = day - diff
                else:
                    month = month - 1
                    day = 31
            elif jday < julian:
                if day + diff < 28:
                    day = day + diff
                else:
                    month = month + 1
        return year, month, day
    month = m.group('month')
    day = 1
    if month is None:
        month = 1
    else:
        month = int(month)
        day = m.group('day')
        if day:
            day = int(day)
        else:
            day = 1
    return year, month, day


# Copied from feedparser.py
# Universal Feedparser
# Copyright (c) 2002-2006, Mark Pilgrim, All rights reserved.
# Originally a def inside of _parse_date_w3dtf()
def _extract_time(m):
    if not m:
        return 0, 0, 0
    hours = m.group('hours')
    if not hours:
        return 0, 0, 0
    hours = int(hours)
    minutes = int(m.group('minutes'))
    seconds = m.group('seconds')
    if seconds:
        seconds = seconds.replace(',', '.').split('.', 1)[0]
        seconds = int(seconds)
    else:
        seconds = 0
    return hours, minutes, seconds


def _pop_time_accuracy(m, ctx):
    if not m:
        return
    if m.group('hours'):
        ctx.updateAccuracy(ctx.ACU_HOUR)
    if m.group('minutes'):
        ctx.updateAccuracy(ctx.ACU_MIN)
    if m.group('seconds'):
        ctx.updateAccuracy(ctx.ACU_SEC)


# Copied from feedparser.py
# Universal Feedparser
# Copyright (c) 2002-2006, Mark Pilgrim, All rights reserved.
# Modified to return a tuple instead of mktime
#
# Original comment:
#   W3DTF-style date parsing adapted from PyXML xml.utils.iso8601, written by
#   Drake and licensed under the Python license.  Removed all range checking
#   for month, day, hour, minute, and second, since mktime will normalize
#   these later
def __closure_parse_date_w3dtf():
    # the __extract_date and __extract_time methods were
    # copied-out so they could be used by my code --bear
    def __extract_tzd(m):
        '''Return the Time Zone Designator as an offset in seconds from UTC.'''
        if not m:
            return 0
        tzd = m.group('tzd')
        if not tzd:
            return 0
        if tzd == 'Z':
            return 0
        hours = int(m.group('tzdhours'))
        minutes = m.group('tzdminutes')
        if minutes:
            minutes = int(minutes)
        else:
            minutes = 0
        offset = (hours * 60 + minutes) * 60
        if tzd[0] == '+':
            return -offset
        return offset

    def _parse_date_w3dtf(dateString):
        m = __datetime_rx.match(dateString)
        if m is None or m.group() != dateString:
            return
        return _extract_date(m) + _extract_time(m) + (0, 0, 0)

    __date_re = (r'(?P<year>\d\d\d\d)'
                 r'(?:(?P<dsep>-|)'
                 r'(?:(?P<julian>\d\d\d)'
                 r'|(?P<month>\d\d)(?:(?P=dsep)(?P<day>\d\d))?))?')
    __tzd_re = r'(?P<tzd>[-+](?P<tzdhours>\d\d)(?::?(?P<tzdminutes>\d\d))|Z)'
    # __tzd_rx = re.compile(__tzd_re)
    __time_re = (r'(?P<hours>\d\d)(?P<tsep>:|)(?P<minutes>\d\d)'
                 r'(?:(?P=tsep)(?P<seconds>\d\d(?:[.,]\d+)?))?' +
                 __tzd_re)
    __datetime_re = '%s(?:T%s)?' % (__date_re, __time_re)
    __datetime_rx = re.compile(__datetime_re)

    return _parse_date_w3dtf


_parse_date_w3dtf = __closure_parse_date_w3dtf()
del __closure_parse_date_w3dtf

_monthnames = set([
    'jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul',
    'aug', 'sep', 'oct', 'nov', 'dec',
    'january', 'february', 'march', 'april', 'may', 'june', 'july',
    'august', 'september', 'october', 'november', 'december'])
_daynames = set(['mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun'])


# Copied from feedparser.py
# Universal Feedparser
# Copyright (c) 2002-2006, Mark Pilgrim, All rights reserved.
# Modified to return a tuple instead of mktime
def _parse_date_rfc822(dateString):
    '''Parse an RFC822, RFC1123, RFC2822, or asctime-style date'''
    data = dateString.split()
    if data[0][-1] in (',', '.') or data[0].lower() in _daynames:
        del data[0]
    if len(data) == 4:
        s = data[3]
        s = s.split('+', 1)
        if len(s) == 2:
            data[3:] = s
        else:
            data.append('')
        dateString = " ".join(data)
    if len(data) < 5:
        dateString += ' 00:00:00 GMT'
    return email.utils.parsedate_tz(dateString)


# rfc822.py defines several time zones, but we define some extra ones.
# 'ET' is equivalent to 'EST', etc.
# _additional_timezones = {'AT': -400, 'ET': -500,
#                          'CT': -600, 'MT': -700,
#                          'PT': -800}
# email.utils._timezones.update(_additional_timezones)

VERSION_FLAG_STYLE = 1
VERSION_CONTEXT_STYLE = 2


class Calendar(object):

    """
    A collection of routines to input, parse and manipulate date and times.
    The text can either be 'normal' date values or it can be human readable.
    """

    def __init__(self, constants=None, version=VERSION_FLAG_STYLE):
        """
        Default constructor for the L{Calendar} class.

        @type  constants: object
        @param constants: Instance of the class L{Constants}
        @type  version:   integer
        @param version:   Default style version of current Calendar instance.
                          Valid value can be 1 (L{VERSION_FLAG_STYLE}) or
                          2 (L{VERSION_CONTEXT_STYLE}). See L{parse()}.

        @rtype:  object
        @return: L{Calendar} instance
        """
        # if a constants reference is not included, use default
        if constants is None:
            self.ptc = Constants()
        else:
            self.ptc = constants

        self.version = version
        if version == VERSION_FLAG_STYLE:
            warnings.warn(
                'Flag style will be deprecated in parsedatetime 2.0. '
                'Instead use the context style by instantiating `Calendar()` '
                'with argument `version=parsedatetime.VERSION_CONTEXT_STYLE`.',
                pdt20DeprecationWarning)
        self._ctxStack = pdtContextStack()

    @contextlib.contextmanager
    def context(self):
        ctx = pdtContext()
        self._ctxStack.push(ctx)
        yield ctx
        ctx = self._ctxStack.pop()
        if not self._ctxStack.isEmpty():
            self.currentContext.update(ctx)

    @property
    def currentContext(self):
        return self._ctxStack.last()

    def _convertUnitAsWords(self, unitText):
        """
        Converts text units into their number value.

        @type  unitText: string
        @param unitText: number text to convert

        @rtype:  integer
        @return: numerical value of unitText
        """
        word_list, a, b = re.split(r"[,\s-]+", unitText), 0, 0
        for word in word_list:
            x = self.ptc.small.get(word)
            if x is not None:
                a += x
            elif word == "hundred":
                a *= 100
            else:
                x = self.ptc.magnitude.get(word)
                if x is not None:
                    b += a * x
                    a = 0
                elif word in self.ptc.ignore:
                    pass
                else:
                    raise Exception("Unknown number: " + word)
        return a + b

    def _buildTime(self, source, quantity, modifier, units):
        """
        Take C{quantity}, C{modifier} and C{unit} strings and convert them
        into values. After converting, calcuate the time and return the
        adjusted sourceTime.

        @type  source:   time
        @param source:   time to use as the base (or source)
        @type  quantity: string
        @param quantity: quantity string
        @type  modifier: string
        @param modifier: how quantity and units modify the source time
        @type  units:    string
        @param units:    unit of the quantity (i.e. hours, days, months, etc)

        @rtype:  struct_time
        @return: C{struct_time} of the calculated time
        """
        ctx = self.currentContext
        debug and log.debug('_buildTime: [%s][%s][%s]',
                            quantity, modifier, units)

        if source is None:
            source = time.localtime()

        if quantity is None:
            quantity = ''
        else:
            quantity = quantity.strip()

        qty = self._quantityToReal(quantity)

        if modifier in self.ptc.Modifiers:
            qty = qty * self.ptc.Modifiers[modifier]

            if units is None or units == '':
                units = 'dy'

        # plurals are handled by regex's (could be a bug tho)

        (yr, mth, dy, hr, mn, sec, _, _, _) = source

        start = datetime.datetime(yr, mth, dy, hr, mn, sec)
        target = start
        # realunit = next((key for key, values in self.ptc.units.items()
        #                  if any(imap(units.__contains__, values))), None)
        realunit = units
        for key, values in self.ptc.units.items():
            if units in values:
                realunit = key
                break

        debug and log.debug('units %s --> realunit %s (qty=%s)',
                            units, realunit, qty)

        try:
            if realunit in ('years', 'months'):
                target = self.inc(start, **{realunit[:-1]: qty})
            elif realunit in ('days', 'hours', 'minutes', 'seconds', 'weeks'):
                delta = datetime.timedelta(**{realunit: qty})
                target = start + delta
        except OverflowError:
            # OverflowError is raise when target.year larger than 9999
            pass
        else:
            ctx.updateAccuracy(realunit)

        return target.timetuple()

    def parseDate(self, dateString, sourceTime=None):
        """
        Parse short-form date strings::

            '05/28/2006' or '04.21'

        @type  dateString: string
        @param dateString: text to convert to a C{datetime}
        @type  sourceTime:     struct_time
        @param sourceTime:     C{struct_time} value to use as the base

        @rtype:  struct_time
        @return: calculated C{struct_time} value of dateString
        """
        if sourceTime is None:
            yr, mth, dy, hr, mn, sec, wd, yd, isdst = time.localtime()
        else:
            yr, mth, dy, hr, mn, sec, wd, yd, isdst = sourceTime

        # values pulled from regex's will be stored here and later
        # assigned to mth, dy, yr based on information from the locale
        # -1 is used as the marker value because we want zero values
        # to be passed thru so they can be flagged as errors later
        v1 = -1
        v2 = -1
        v3 = -1
        accuracy = []

        s = dateString
        m = self.ptc.CRE_DATE2.search(s)
        if m is not None:
            index = m.start()
            v1 = int(s[:index])
            s = s[index + 1:]

        m = self.ptc.CRE_DATE2.search(s)
        if m is not None:
            index = m.start()
            v2 = int(s[:index])
            v3 = int(s[index + 1:])
        else:
            v2 = int(s.strip())

        v = [v1, v2, v3]
        d = {'m': mth, 'd': dy, 'y': yr}

        # yyyy/mm/dd format
        dp_order = self.ptc.dp_order if v1 <= 31 else ['y', 'm', 'd']

        for i in range(0, 3):
            n = v[i]
            c = dp_order[i]
            if n >= 0:
                d[c] = n
                accuracy.append({'m': pdtContext.ACU_MONTH,
                                 'd': pdtContext.ACU_DAY,
                                 'y': pdtContext.ACU_YEAR}[c])

        # if the year is not specified and the date has already
        # passed, increment the year
        if v3 == -1 and ((mth > d['m']) or (mth == d['m'] and dy > d['d'])):
            yr = d['y'] + self.ptc.YearParseStyle
        else:
            yr = d['y']

        mth = d['m']
        dy = d['d']

        # birthday epoch constraint
        if yr < self.ptc.BirthdayEpoch:
            yr += 2000
        elif yr < 100:
            yr += 1900

        daysInCurrentMonth = self.ptc.daysInMonth(mth, yr)
        debug and log.debug('parseDate: %s %s %s %s',
                            yr, mth, dy, daysInCurrentMonth)

        with self.context() as ctx:
            if mth > 0 and mth <= 12 and dy > 0 and \
                    dy <= daysInCurrentMonth:
                sourceTime = (yr, mth, dy, hr, mn, sec, wd, yd, isdst)
                ctx.updateAccuracy(*accuracy)
            else:
                # return current time if date string is invalid
                sourceTime = time.localtime()

        return sourceTime

    def parseDateText(self, dateString, sourceTime=None):
        """
        Parse long-form date strings::

            'May 31st, 2006'
            'Jan 1st'
            'July 2006'

        @type  dateString: string
        @param dateString: text to convert to a datetime
        @type  sourceTime:     struct_time
        @param sourceTime:     C{struct_time} value to use as the base

        @rtype:  struct_time
        @return: calculated C{struct_time} value of dateString
        """
        if sourceTime is None:
            yr, mth, dy, hr, mn, sec, wd, yd, isdst = time.localtime()
        else:
            yr, mth, dy, hr, mn, sec, wd, yd, isdst = sourceTime

        currentMth = mth
        currentDy = dy
        accuracy = []

        debug and log.debug('parseDateText currentMth %s currentDy %s',
                            mth, dy)

        s = dateString.lower()
        m = self.ptc.CRE_DATE3.search(s)
        mth = m.group('mthname')
        mth = self.ptc.MonthOffsets[mth]
        accuracy.append('month')

        if m.group('day') is not None:
            dy = int(m.group('day'))
            accuracy.append('day')
        else:
            dy = 1

        if m.group('year') is not None:
            yr = int(m.group('year'))
            accuracy.append('year')

            # birthday epoch constraint
            if yr < self.ptc.BirthdayEpoch:
                yr += 2000
            elif yr < 100:
                yr += 1900

        elif (mth < currentMth) or (mth == currentMth and dy < currentDy):
            # if that day and month have already passed in this year,
            # then increment the year by 1
            yr += self.ptc.YearParseStyle

        with self.context() as ctx:
            if dy > 0 and dy <= self.ptc.daysInMonth(mth, yr):
                sourceTime = (yr, mth, dy, hr, mn, sec, wd, yd, isdst)
                ctx.updateAccuracy(*accuracy)
            else:
                # Return current time if date string is invalid
                sourceTime = time.localtime()

        debug and log.debug('parseDateText returned '
                            'mth %d dy %d yr %d sourceTime %s',
                            mth, dy, yr, sourceTime)

        return sourceTime

    def evalRanges(self, datetimeString, sourceTime=None):
        """
        Evaluate the C{datetimeString} text and determine if
        it represents a date or time range.

        @type  datetimeString: string
        @param datetimeString: datetime text to evaluate
        @type  sourceTime:     struct_time
        @param sourceTime:     C{struct_time} value to use as the base

        @rtype:  tuple
        @return: tuple of: start datetime, end datetime and the invalid flag
        """
        rangeFlag = retFlag = 0
        startStr = endStr = ''

        s = datetimeString.strip().lower()

        if self.ptc.rangeSep in s:
            s = s.replace(self.ptc.rangeSep, ' %s ' % self.ptc.rangeSep)
            s = s.replace('  ', ' ')

        for cre, rflag in [(self.ptc.CRE_TIMERNG1, 1),
                           (self.ptc.CRE_TIMERNG2, 2),
                           (self.ptc.CRE_TIMERNG4, 7),
                           (self.ptc.CRE_TIMERNG3, 3),
                           (self.ptc.CRE_DATERNG1, 4),
                           (self.ptc.CRE_DATERNG2, 5),
                           (self.ptc.CRE_DATERNG3, 6)]:
            m = cre.search(s)
            if m is not None:
                rangeFlag = rflag
                break

        debug and log.debug('evalRanges: rangeFlag = %s [%s]', rangeFlag, s)

        if m is not None:
            if (m.group() != s):
                # capture remaining string
                parseStr = m.group()
                chunk1 = s[:m.start()]
                chunk2 = s[m.end():]
                s = '%s %s' % (chunk1, chunk2)

                sourceTime, ctx = self.parse(s, sourceTime,
                                             VERSION_CONTEXT_STYLE)

                if not ctx.hasDateOrTime:
                    sourceTime = None
            else:
                parseStr = s

        if rangeFlag in (1, 2):
            m = re.search(self.ptc.rangeSep, parseStr)
            startStr = parseStr[:m.start()]
            endStr = parseStr[m.start() + 1:]
            retFlag = 2

        elif rangeFlag in (3, 7):
            m = re.search(self.ptc.rangeSep, parseStr)
            # capturing the meridian from the end time
            if self.ptc.usesMeridian:
                ampm = re.search(self.ptc.am[0], parseStr)

                # appending the meridian to the start time
                if ampm is not None:
                    startStr = parseStr[:m.start()] + self.ptc.meridian[0]
                else:
                    startStr = parseStr[:m.start()] + self.ptc.meridian[1]
            else:
                startStr = parseStr[:m.start()]

            endStr = parseStr[m.start() + 1:]
            retFlag = 2

        elif rangeFlag == 4:
            m = re.search(self.ptc.rangeSep, parseStr)
            startStr = parseStr[:m.start()]
            endStr = parseStr[m.start() + 1:]
            retFlag = 1

        elif rangeFlag == 5:
            m = re.search(self.ptc.rangeSep, parseStr)
            endStr = parseStr[m.start() + 1:]

            # capturing the year from the end date
            date = self.ptc.CRE_DATE3.search(endStr)
            endYear = date.group('year')

            # appending the year to the start date if the start date
            # does not have year information and the end date does.
            # eg : "Aug 21 - Sep 4, 2007"
            if endYear is not None:
                startStr = (parseStr[:m.start()]).strip()
                date = self.ptc.CRE_DATE3.search(startStr)
                startYear = date.group('year')

                if startYear is None:
                    startStr = startStr + ', ' + endYear
            else:
                startStr = parseStr[:m.start()]

            retFlag = 1

        elif rangeFlag == 6:
            m = re.search(self.ptc.rangeSep, parseStr)

            startStr = parseStr[:m.start()]

            # capturing the month from the start date
            mth = self.ptc.CRE_DATE3.search(startStr)
            mth = mth.group('mthname')

            # appending the month name to the end date
            endStr = mth + parseStr[(m.start() + 1):]

            retFlag = 1

        else:
            # if range is not found
            startDT = endDT = time.localtime()

        if retFlag:
            startDT, sctx = self.parse(startStr, sourceTime,
                                       VERSION_CONTEXT_STYLE)
            endDT, ectx = self.parse(endStr, sourceTime,
                                     VERSION_CONTEXT_STYLE)

            if not sctx.hasDateOrTime or not ectx.hasDateOrTime:
                retFlag = 0

        return startDT, endDT, retFlag

    def _CalculateDOWDelta(self, wd, wkdy, offset, style, currentDayStyle):
        """
        Based on the C{style} and C{currentDayStyle} determine what
        day-of-week value is to be returned.

        @type  wd:              integer
        @param wd:              day-of-week value for the current day
        @type  wkdy:            integer
        @param wkdy:            day-of-week value for the parsed day
        @type  offset:          integer
        @param offset:          offset direction for any modifiers (-1, 0, 1)
        @type  style:           integer
        @param style:           normally the value
                                set in C{Constants.DOWParseStyle}
        @type  currentDayStyle: integer
        @param currentDayStyle: normally the value
                                set in C{Constants.CurrentDOWParseStyle}

        @rtype:  integer
        @return: calculated day-of-week
        """
        diffBase = wkdy - wd
        origOffset = offset

        if offset == 2:
            # no modifier is present.
            # i.e. string to be parsed is just DOW
            if wkdy * style > wd * style or \
                    currentDayStyle and wkdy == wd:
                # wkdy located in current week
                offset = 0
            elif style in (-1, 1):
                # wkdy located in last (-1) or next (1) week
                offset = style
            else:
                # invalid style, or should raise error?
                offset = 0

        # offset = -1 means last week
        # offset = 0 means current week
        # offset = 1 means next week
        diff = diffBase + 7 * offset
        if style == 1 and diff < -7:
            diff += 7
        elif style == -1 and diff > 7:
            diff -= 7

        debug and log.debug("wd %s, wkdy %s, offset %d, "
                            "style %d, currentDayStyle %d",
                            wd, wkdy, origOffset, style, currentDayStyle)

        return diff

    def _quantityToReal(self, quantity):
        """
        Convert a quantity, either spelled-out or numeric, to a float

        @type    quantity: string
        @param   quantity: quantity to parse to float
        @rtype:  int
        @return: the quantity as an float, defaulting to 0.0
        """
        if not quantity:
            return 1.0

        try:
            return float(quantity.replace(',', '.'))
        except ValueError:
            pass

        try:
            return float(self.ptc.numbers[quantity])
        except KeyError:
            pass

        return 0.0

    def _evalModifier(self, modifier, chunk1, chunk2, sourceTime):
        """
        Evaluate the C{modifier} string and following text (passed in
        as C{chunk1} and C{chunk2}) and if they match any known modifiers
        calculate the delta and apply it to C{sourceTime}.

        @type  modifier:   string
        @param modifier:   modifier text to apply to sourceTime
        @type  chunk1:     string
        @param chunk1:     text chunk that preceded modifier (if any)
        @type  chunk2:     string
        @param chunk2:     text chunk that followed modifier (if any)
        @type  sourceTime: struct_time
        @param sourceTime: C{struct_time} value to use as the base

        @rtype:  tuple
        @return: tuple of: remaining text and the modified sourceTime
        """
        ctx = self.currentContext
        offset = self.ptc.Modifiers[modifier]

        if sourceTime is not None:
            (yr, mth, dy, hr, mn, sec, wd, yd, isdst) = sourceTime
        else:
            (yr, mth, dy, hr, mn, sec, wd, yd, isdst) = time.localtime()

        if self.ptc.StartTimeFromSourceTime:
            startHour = hr
            startMinute = mn
            startSecond = sec
        else:
            startHour = 9
            startMinute = 0
            startSecond = 0

        # capture the units after the modifier and the remaining
        # string after the unit
        m = self.ptc.CRE_REMAINING.search(chunk2)
        if m is not None:
            index = m.start() + 1
            unit = chunk2[:m.start()]
            chunk2 = chunk2[index:]
        else:
            unit = chunk2
            chunk2 = ''

        debug and log.debug("modifier [%s] chunk1 [%s] "
                            "chunk2 [%s] unit [%s]",
                            modifier, chunk1, chunk2, unit)

        if unit in self.ptc.units['months']:
            currentDaysInMonth = self.ptc.daysInMonth(mth, yr)
            if offset == 0:
                dy = currentDaysInMonth
                sourceTime = (yr, mth, dy, startHour, startMinute,
                              startSecond, wd, yd, isdst)
            elif offset == 2:
                # if day is the last day of the month, calculate the last day
                # of the next month
                if dy == currentDaysInMonth:
                    dy = self.ptc.daysInMonth(mth + 1, yr)

                start = datetime.datetime(yr, mth, dy, startHour,
                                          startMinute, startSecond)
                target = self.inc(start, month=1)
                sourceTime = target.timetuple()
            else:
                start = datetime.datetime(yr, mth, 1, startHour,
                                          startMinute, startSecond)
                target = self.inc(start, month=offset)
                sourceTime = target.timetuple()
            ctx.updateAccuracy(ctx.ACU_MONTH)

        elif unit in self.ptc.units['weeks']:
            if offset == 0:
                start = datetime.datetime(yr, mth, dy, 17, 0, 0)
                target = start + datetime.timedelta(days=(4 - wd))
                sourceTime = target.timetuple()
            elif offset == 2:
                start = datetime.datetime(yr, mth, dy, startHour,
                                          startMinute, startSecond)
                target = start + datetime.timedelta(days=7)
                sourceTime = target.timetuple()
            else:
                start = datetime.datetime(yr, mth, dy, startHour,
                                          startMinute, startSecond)
                target = start + offset * datetime.timedelta(weeks=1)
                sourceTime = target.timetuple()
            ctx.updateAccuracy(ctx.ACU_WEEK)

        elif unit in self.ptc.units['days']:
            if offset == 0:
                sourceTime = (yr, mth, dy, 17, 0, 0, wd, yd, isdst)
                ctx.updateAccuracy(ctx.ACU_HALFDAY)
            elif offset == 2:
                start = datetime.datetime(yr, mth, dy, hr, mn, sec)
                target = start + datetime.timedelta(days=1)
                sourceTime = target.timetuple()
            else:
                start = datetime.datetime(yr, mth, dy, startHour,
                                          startMinute, startSecond)
                target = start + datetime.timedelta(days=offset)
                sourceTime = target.timetuple()
            ctx.updateAccuracy(ctx.ACU_DAY)

        elif unit in self.ptc.units['hours']:
            if offset == 0:
                sourceTime = (yr, mth, dy, hr, 0, 0, wd, yd, isdst)
            else:
                start = datetime.datetime(yr, mth, dy, hr, 0, 0)
                target = start + datetime.timedelta(hours=offset)
                sourceTime = target.timetuple()
            ctx.updateAccuracy(ctx.ACU_HOUR)

        elif unit in self.ptc.units['years']:
            if offset == 0:
                sourceTime = (yr, 12, 31, hr, mn, sec, wd, yd, isdst)
            elif offset == 2:
                sourceTime = (yr + 1, mth, dy, hr, mn, sec, wd, yd, isdst)
            else:
                sourceTime = (yr + offset, 1, 1, startHour, startMinute,
                              startSecond, wd, yd, isdst)
            ctx.updateAccuracy(ctx.ACU_YEAR)

        elif modifier == 'eom':
            dy = self.ptc.daysInMonth(mth, yr)
            sourceTime = (yr, mth, dy, startHour, startMinute,
                          startSecond, wd, yd, isdst)
            ctx.updateAccuracy(ctx.ACU_DAY)

        elif modifier == 'eoy':
            mth = 12
            dy = self.ptc.daysInMonth(mth, yr)
            sourceTime = (yr, mth, dy, startHour, startMinute,
                          startSecond, wd, yd, isdst)
            ctx.updateAccuracy(ctx.ACU_MONTH)

        elif self.ptc.CRE_WEEKDAY.match(unit):
            m = self.ptc.CRE_WEEKDAY.match(unit)
            debug and log.debug('CRE_WEEKDAY matched')
            wkdy = m.group()

            if modifier == 'eod':
                ctx.updateAccuracy(ctx.ACU_HOUR)
                # Calculate the upcoming weekday
                sourceTime, subctx = self.parse(wkdy, sourceTime,
                                                VERSION_CONTEXT_STYLE)
                sTime = self.ptc.getSource(modifier, sourceTime)
                if sTime is not None:
                    sourceTime = sTime
                    ctx.updateAccuracy(ctx.ACU_HALFDAY)
            else:
                # unless one of these modifiers is being applied to the
                # day-of-week, we want to start with target as the day
                # in the current week.
                dowOffset = offset
                relativeModifier = modifier not in ['this', 'next', 'last', 'prior', 'previous']
                if relativeModifier:
                    dowOffset = 0

                wkdy = self.ptc.WeekdayOffsets[wkdy]
                diff = self._CalculateDOWDelta(
                    wd, wkdy, dowOffset, self.ptc.DOWParseStyle,
                    self.ptc.CurrentDOWParseStyle)
                start = datetime.datetime(yr, mth, dy, startHour,
                                          startMinute, startSecond)
                target = start + datetime.timedelta(days=diff)

                if chunk1 != '' and relativeModifier:
                    # consider "one day before thursday": we need to parse chunk1 ("one day")
                    # and apply according to the offset ("before"), rather than allowing the
                    # remaining parse step to apply "one day" without the offset direction.
                    t, subctx = self.parse(chunk1, sourceTime, VERSION_CONTEXT_STYLE)
                    if subctx.hasDateOrTime:
                        delta = time.mktime(t) - time.mktime(sourceTime)
                        target = start + datetime.timedelta(days=diff) + datetime.timedelta(seconds=delta * offset)
                        chunk1 = ''

                sourceTime = target.timetuple()
            ctx.updateAccuracy(ctx.ACU_DAY)

        elif chunk1 == '' and chunk2 == '' and self.ptc.CRE_TIME.match(unit):
            m = self.ptc.CRE_TIME.match(unit)
            debug and log.debug('CRE_TIME matched')
            (yr, mth, dy, hr, mn, sec, wd, yd, isdst), subctx = \
                self.parse(unit, None, VERSION_CONTEXT_STYLE)

            start = datetime.datetime(yr, mth, dy, hr, mn, sec)
            target = start + datetime.timedelta(days=offset)
            sourceTime = target.timetuple()

        else:
            # check if the remaining text is parsable and if so,
            # use it as the base time for the modifier source time

            debug and log.debug('check for modifications '
                                'to source time [%s] [%s]',
                                chunk1, unit)

            unit = unit.strip()
            if unit:
                s = '%s %s' % (unit, chunk2)
                t, subctx = self.parse(s, sourceTime, VERSION_CONTEXT_STYLE)

                if subctx.hasDate:  # working with dates
                    u = unit.lower()
                    if u in self.ptc.Months or \
                            u in self.ptc.shortMonths:
                        yr, mth, dy, hr, mn, sec, wd, yd, isdst = t
                        start = datetime.datetime(
                            yr, mth, dy, hr, mn, sec)
                        t = self.inc(start, year=offset).timetuple()
                    elif u in self.ptc.Weekdays:
                        t = t + datetime.timedelta(weeks=offset)

                if subctx.hasDateOrTime:
                    sourceTime = t
                    chunk2 = ''

            chunk1 = chunk1.strip()

            # if the word after next is a number, the string is more than
            # likely to be "next 4 hrs" which we will have to combine the
            # units with the rest of the string
            if chunk1:
                try:
                    m = list(self.ptc.CRE_NUMBER.finditer(chunk1))[-1]
                except IndexError:
                    pass
                else:
                    qty = None
                    debug and log.debug('CRE_NUMBER matched')
                    qty = self._quantityToReal(m.group()) * offset
                    chunk1 = '%s%s%s' % (chunk1[:m.start()],
                                         qty, chunk1[m.end():])
                t, subctx = self.parse(chunk1, sourceTime,
                                       VERSION_CONTEXT_STYLE)

                chunk1 = ''

                if subctx.hasDateOrTime:
                    sourceTime = t

            debug and log.debug('looking for modifier %s', modifier)
            sTime = self.ptc.getSource(modifier, sourceTime)
            if sTime is not None:
                debug and log.debug('modifier found in sources')
                sourceTime = sTime
                ctx.updateAccuracy(ctx.ACU_HALFDAY)

        debug and log.debug('returning chunk = "%s %s" and sourceTime = %s',
                            chunk1, chunk2, sourceTime)

        return '%s %s' % (chunk1, chunk2), sourceTime

    def _evalDT(self, datetimeString, sourceTime):
        """
        Calculate the datetime from known format like RFC822 or W3CDTF

        Examples handled::
            RFC822, W3CDTF formatted dates
            HH:MM[:SS][ am/pm]
            MM/DD/YYYY
            DD MMMM YYYY

        @type  datetimeString: string
        @param datetimeString: text to try and parse as more "traditional"
                               date/time text
        @type  sourceTime:     struct_time
        @param sourceTime:     C{struct_time} value to use as the base

        @rtype:  datetime
        @return: calculated C{struct_time} value or current C{struct_time}
                 if not parsed
        """
        ctx = self.currentContext
        s = datetimeString.strip()

        # Given string date is a RFC822 date
        if sourceTime is None:
            sourceTime = _parse_date_rfc822(s)
            debug and log.debug(
                'attempt to parse as rfc822 - %s', str(sourceTime))

            if sourceTime is not None:
                (yr, mth, dy, hr, mn, sec, wd, yd, isdst, _) = sourceTime
                ctx.updateAccuracy(ctx.ACU_YEAR, ctx.ACU_MONTH, ctx.ACU_DAY)

                if hr != 0 and mn != 0 and sec != 0:
                    ctx.updateAccuracy(ctx.ACU_HOUR, ctx.ACU_MIN, ctx.ACU_SEC)

                sourceTime = (yr, mth, dy, hr, mn, sec, wd, yd, isdst)

        # Given string date is a W3CDTF date
        if sourceTime is None:
            sourceTime = _parse_date_w3dtf(s)

            if sourceTime is not None:
                ctx.updateAccuracy(ctx.ACU_YEAR, ctx.ACU_MONTH, ctx.ACU_DAY,
                                   ctx.ACU_HOUR, ctx.ACU_MIN, ctx.ACU_SEC)

        if sourceTime is None:
            sourceTime = time.localtime()

        return sourceTime

    def _evalUnits(self, datetimeString, sourceTime):
        """
        Evaluate text passed by L{_partialParseUnits()}
        """
        s = datetimeString.strip()
        sourceTime = self._evalDT(datetimeString, sourceTime)

        # Given string is a time string with units like "5 hrs 30 min"
        modifier = ''  # TODO

        m = self.ptc.CRE_UNITS.search(s)
        if m is not None:
            units = m.group('units')
            quantity = s[:m.start('units')]

        sourceTime = self._buildTime(sourceTime, quantity, modifier, units)
        return sourceTime

    def _evalQUnits(self, datetimeString, sourceTime):
        """
        Evaluate text passed by L{_partialParseQUnits()}
        """
        s = datetimeString.strip()
        sourceTime = self._evalDT(datetimeString, sourceTime)

        # Given string is a time string with single char units like "5 h 30 m"
        modifier = ''  # TODO

        m = self.ptc.CRE_QUNITS.search(s)
        if m is not None:
            units = m.group('qunits')
            quantity = s[:m.start('qunits')]

        sourceTime = self._buildTime(sourceTime, quantity, modifier, units)
        return sourceTime

    def _evalDateStr(self, datetimeString, sourceTime):
        """
        Evaluate text passed by L{_partialParseDateStr()}
        """
        s = datetimeString.strip()
        sourceTime = self._evalDT(datetimeString, sourceTime)

        # Given string is in the format  "May 23rd, 2005"
        debug and log.debug('checking for MMM DD YYYY')
        return self.parseDateText(s, sourceTime)

    def _evalDateStd(self, datetimeString, sourceTime):
        """
        Evaluate text passed by L{_partialParseDateStd()}
        """
        s = datetimeString.strip()
        sourceTime = self._evalDT(datetimeString, sourceTime)

        # Given string is in the format 07/21/2006
        return self.parseDate(s, sourceTime)

    def _evalDayStr(self, datetimeString, sourceTime):
        """
        Evaluate text passed by L{_partialParseDaystr()}
        """
        s = datetimeString.strip()
        sourceTime = self._evalDT(datetimeString, sourceTime)

        # Given string is a natural language date string like today, tomorrow..
        (yr, mth, dy, hr, mn, sec, wd, yd, isdst) = sourceTime

        try:
            offset = self.ptc.dayOffsets[s]
        except KeyError:
            offset = 0

        if self.ptc.StartTimeFromSourceTime:
            startHour = hr
            startMinute = mn
            startSecond = sec
        else:
            startHour = 9
            startMinute = 0
            startSecond = 0

        self.currentContext.updateAccuracy(pdtContext.ACU_DAY)
        start = datetime.datetime(yr, mth, dy, startHour,
                                  startMinute, startSecond)
        target = start + datetime.timedelta(days=offset)
        return target.timetuple()

    def _evalWeekday(self, datetimeString, sourceTime):
        """
        Evaluate text passed by L{_partialParseWeekday()}
        """
        s = datetimeString.strip()
        sourceTime = self._evalDT(datetimeString, sourceTime)

        # Given string is a weekday
        yr, mth, dy, hr, mn, sec, wd, yd, isdst = sourceTime

        start = datetime.datetime(yr, mth, dy, hr, mn, sec)
        wkdy = self.ptc.WeekdayOffsets[s]

        if wkdy > wd:
            qty = self._CalculateDOWDelta(wd, wkdy, 2,
                                          self.ptc.DOWParseStyle,
                                          self.ptc.CurrentDOWParseStyle)
        else:
            qty = self._CalculateDOWDelta(wd, wkdy, 2,
                                          self.ptc.DOWParseStyle,
                                          self.ptc.CurrentDOWParseStyle)

        self.currentContext.updateAccuracy(pdtContext.ACU_DAY)
        target = start + datetime.timedelta(days=qty)
        return target.timetuple()

    def _evalTimeStr(self, datetimeString, sourceTime):
        """
        Evaluate text passed by L{_partialParseTimeStr()}
        """
        s = datetimeString.strip()
        sourceTime = self._evalDT(datetimeString, sourceTime)

        if s in self.ptc.re_values['now']:
            self.currentContext.updateAccuracy(pdtContext.ACU_NOW)
        else:
            # Given string is a natural language time string like
            # lunch, midnight, etc
            sTime = self.ptc.getSource(s, sourceTime)
            if sTime:
                sourceTime = sTime
            self.currentContext.updateAccuracy(pdtContext.ACU_HALFDAY)

        return sourceTime

    def _evalMeridian(self, datetimeString, sourceTime):
        """
        Evaluate text passed by L{_partialParseMeridian()}
        """
        s = datetimeString.strip()
        sourceTime = self._evalDT(datetimeString, sourceTime)

        # Given string is in the format HH:MM(:SS)(am/pm)
        yr, mth, dy, hr, mn, sec, wd, yd, isdst = sourceTime

        m = self.ptc.CRE_TIMEHMS2.search(s)
        if m is not None:
            dt = s[:m.start('meridian')].strip()
            if len(dt) <= 2:
                hr = int(dt)
                mn = 0
                sec = 0
            else:
                hr, mn, sec = _extract_time(m)

            if hr == 24:
                hr = 0

            meridian = m.group('meridian').lower()

            # if 'am' found and hour is 12 - force hour to 0 (midnight)
            if (meridian in self.ptc.am) and hr == 12:
                hr = 0

            # if 'pm' found and hour < 12, add 12 to shift to evening
            if (meridian in self.ptc.pm) and hr < 12:
                hr += 12

        # time validation
        if hr < 24 and mn < 60 and sec < 60:
            sourceTime = (yr, mth, dy, hr, mn, sec, wd, yd, isdst)
            _pop_time_accuracy(m, self.currentContext)

        return sourceTime

    def _evalTimeStd(self, datetimeString, sourceTime):
        """
        Evaluate text passed by L{_partialParseTimeStd()}
        """
        s = datetimeString.strip()
        sourceTime = self._evalDT(datetimeString, sourceTime)

        # Given string is in the format HH:MM(:SS)
        yr, mth, dy, hr, mn, sec, wd, yd, isdst = sourceTime

        m = self.ptc.CRE_TIMEHMS.search(s)
        if m is not None:
            hr, mn, sec = _extract_time(m)
        if hr == 24:
            hr = 0

        # time validation
        if hr < 24 and mn < 60 and sec < 60:
            sourceTime = (yr, mth, dy, hr, mn, sec, wd, yd, isdst)
            _pop_time_accuracy(m, self.currentContext)

        return sourceTime

    def _UnitsTrapped(self, s, m, key):
        # check if a day suffix got trapped by a unit match
        # for example Dec 31st would match for 31s (aka 31 seconds)
        # Dec 31st
        #     ^ ^
        #     | +-- m.start('units')
        #     |     and also m2.start('suffix')
        #     +---- m.start('qty')
        #           and also m2.start('day')
        m2 = self.ptc.CRE_DAY2.search(s)
        if m2 is not None:
            t = '%s%s' % (m2.group('day'), m.group(key))
            if m.start(key) == m2.start('suffix') and \
                    m.start('qty') == m2.start('day') and \
                    m.group('qty') == t:
                return True
            else:
                return False
        else:
            return False

    def _partialParseModifier(self, s, sourceTime):
        """
        test if giving C{s} matched CRE_MODIFIER, used by L{parse()}

        @type  s:          string
        @param s:          date/time text to evaluate
        @type  sourceTime: struct_time
        @param sourceTime: C{struct_time} value to use as the base

        @rtype:  tuple
        @return: tuple of remained date/time text, datetime object and
                 an boolean value to describ if matched or not

        """
        parseStr = None
        chunk1 = chunk2 = ''

        # Modifier like next/prev/from/after/prior..
        m = self.ptc.CRE_MODIFIER.search(s)
        if m is not None:
            if m.group() != s:
                # capture remaining string
                parseStr = m.group()
                chunk1 = s[:m.start()].strip()
                chunk2 = s[m.end():].strip()
            else:
                parseStr = s

        if parseStr:
            debug and log.debug('found (modifier) [%s][%s][%s]',
                                parseStr, chunk1, chunk2)
            s, sourceTime = self._evalModifier(parseStr, chunk1,
                                               chunk2, sourceTime)

        return s, sourceTime, bool(parseStr)

    def _partialParseUnits(self, s, sourceTime):
        """
        test if giving C{s} matched CRE_UNITS, used by L{parse()}

        @type  s:          string
        @param s:          date/time text to evaluate
        @type  sourceTime: struct_time
        @param sourceTime: C{struct_time} value to use as the base

        @rtype:  tuple
        @return: tuple of remained date/time text, datetime object and
                 an boolean value to describ if matched or not

        """
        parseStr = None
        chunk1 = chunk2 = ''

        # Quantity + Units
        m = self.ptc.CRE_UNITS.search(s)
        if m is not None:
            debug and log.debug('CRE_UNITS matched')
            if self._UnitsTrapped(s, m, 'units'):
                debug and log.debug('day suffix trapped by unit match')
            else:
                if (m.group('qty') != s):
                    # capture remaining string
                    parseStr = m.group('qty')
                    chunk1 = s[:m.start('qty')].strip()
                    chunk2 = s[m.end('qty'):].strip()

                    if chunk1[-1:] == '-':
                        parseStr = '-%s' % parseStr
                        chunk1 = chunk1[:-1]

                    s = '%s %s' % (chunk1, chunk2)
                else:
                    parseStr = s
                    s = ''

        if parseStr:
            debug and log.debug('found (units) [%s][%s][%s]',
                                parseStr, chunk1, chunk2)
            sourceTime = self._evalUnits(parseStr, sourceTime)

        return s, sourceTime, bool(parseStr)

    def _partialParseQUnits(self, s, sourceTime):
        """
        test if giving C{s} matched CRE_QUNITS, used by L{parse()}

        @type  s:          string
        @param s:          date/time text to evaluate
        @type  sourceTime: struct_time
        @param sourceTime: C{struct_time} value to use as the base

        @rtype:  tuple
        @return: tuple of remained date/time text, datetime object and
                 an boolean value to describ if matched or not

        """
        parseStr = None
        chunk1 = chunk2 = ''

        # Quantity + Units
        m = self.ptc.CRE_QUNITS.search(s)
        if m is not None:
            debug and log.debug('CRE_QUNITS matched')
            if self._UnitsTrapped(s, m, 'qunits'):
                debug and log.debug(
                    'day suffix trapped by qunit match')
            else:
                if (m.group('qty') != s):
                    # capture remaining string
                    parseStr = m.group('qty')
                    chunk1 = s[:m.start('qty')].strip()
                    chunk2 = s[m.end('qty'):].strip()

                    if chunk1[-1:] == '-':
                        parseStr = '-%s' % parseStr
                        chunk1 = chunk1[:-1]

                    s = '%s %s' % (chunk1, chunk2)
                else:
                    parseStr = s
                    s = ''

        if parseStr:
            debug and log.debug('found (qunits) [%s][%s][%s]',
                                parseStr, chunk1, chunk2)
            sourceTime = self._evalQUnits(parseStr, sourceTime)

        return s, sourceTime, bool(parseStr)

    def _partialParseDateStr(self, s, sourceTime):
        """
        test if giving C{s} matched CRE_DATE3, used by L{parse()}

        @type  s:          string
        @param s:          date/time text to evaluate
        @type  sourceTime: struct_time
        @param sourceTime: C{struct_time} value to use as the base

        @rtype:  tuple
        @return: tuple of remained date/time text, datetime object and
                 an boolean value to describ if matched or not

        """
        parseStr = None
        chunk1 = chunk2 = ''

        m = self.ptc.CRE_DATE3.search(s)
        # NO LONGER NEEDED, THE REGEXP HANDLED MTHNAME NOW
        # for match in self.ptc.CRE_DATE3.finditer(s):
        # to prevent "HH:MM(:SS) time strings" expressions from
        # triggering this regex, we checks if the month field
        # exists in the searched expression, if it doesn't exist,
        # the date field is not valid
        #     if match.group('mthname'):
        #         m = self.ptc.CRE_DATE3.search(s, match.start())
        #         valid_date = True
        #         break

        # String date format
        if m is not None:

            if (m.group('date') != s):
                # capture remaining string
                mStart = m.start('date')
                mEnd = m.end('date')

                # we need to check that anything following the parsed
                # date is a time expression because it is often picked
                # up as a valid year if the hour is 2 digits
                fTime = False
                mm = self.ptc.CRE_TIMEHMS2.search(s)
                # "February 24th 1PM" doesn't get caught
                # "February 24th 12PM" does
                mYear = m.group('year')
                if mm is not None and mYear is not None:
                    fTime = True
                else:
                    # "February 24th 12:00"
                    mm = self.ptc.CRE_TIMEHMS.search(s)
                    if mm is not None and mYear is None:
                        fTime = True
                if fTime:
                    hoursStart = mm.start('hours')

                    if hoursStart < m.end('year'):
                        mEnd = hoursStart

                parseStr = s[mStart:mEnd]
                chunk1 = s[:mStart]
                chunk2 = s[mEnd:]

                s = '%s %s' % (chunk1, chunk2)
            else:
                parseStr = s
                s = ''

        if parseStr:
            debug and log.debug(
                'found (date3) [%s][%s][%s]', parseStr, chunk1, chunk2)
            sourceTime = self._evalDateStr(parseStr, sourceTime)

        return s, sourceTime, bool(parseStr)

    def _partialParseDateStd(self, s, sourceTime):
        """
        test if giving C{s} matched CRE_DATE, used by L{parse()}

        @type  s:          string
        @param s:          date/time text to evaluate
        @type  sourceTime: struct_time
        @param sourceTime: C{struct_time} value to use as the base

        @rtype:  tuple
        @return: tuple of remained date/time text, datetime object and
                 an boolean value to describ if matched or not

        """
        parseStr = None
        chunk1 = chunk2 = ''

        # Standard date format
        m = self.ptc.CRE_DATE.search(s)
        if m is not None:

            if (m.group('date') != s):
                # capture remaining string
                parseStr = m.group('date')
                chunk1 = s[:m.start('date')]
                chunk2 = s[m.end('date'):]
                s = '%s %s' % (chunk1, chunk2)
            else:
                parseStr = s
                s = ''

        if parseStr:
            debug and log.debug(
                'found (date) [%s][%s][%s]', parseStr, chunk1, chunk2)
            sourceTime = self._evalDateStd(parseStr, sourceTime)

        return s, sourceTime, bool(parseStr)

    def _partialParseDayStr(self, s, sourceTime):
        """
        test if giving C{s} matched CRE_DAY, used by L{parse()}

        @type  s:          string
        @param s:          date/time text to evaluate
        @type  sourceTime: struct_time
        @param sourceTime: C{struct_time} value to use as the base

        @rtype:  tuple
        @return: tuple of remained date/time text, datetime object and
                 an boolean value to describ if matched or not

        """
        parseStr = None
        chunk1 = chunk2 = ''

        # Natural language day strings
        m = self.ptc.CRE_DAY.search(s)
        if m is not None:

            if (m.group() != s):
                # capture remaining string
                parseStr = m.group()
                chunk1 = s[:m.start()]
                chunk2 = s[m.end():]
                s = '%s %s' % (chunk1, chunk2)
            else:
                parseStr = s
                s = ''

        if parseStr:
            debug and log.debug(
                'found (day) [%s][%s][%s]', parseStr, chunk1, chunk2)
            sourceTime = self._evalDayStr(parseStr, sourceTime)

        return s, sourceTime, bool(parseStr)

    def _partialParseWeekday(self, s, sourceTime):
        """
        test if giving C{s} matched CRE_WEEKDAY, used by L{parse()}

        @type  s:          string
        @param s:          date/time text to evaluate
        @type  sourceTime: struct_time
        @param sourceTime: C{struct_time} value to use as the base

        @rtype:  tuple
        @return: tuple of remained date/time text, datetime object and
                 an boolean value to describ if matched or not

        """
        parseStr = None
        chunk1 = chunk2 = ''

        ctx = self.currentContext
        log.debug('eval %s with context - %s, %s', s, ctx.hasDate, ctx.hasTime)

        # Weekday
        m = self.ptc.CRE_WEEKDAY.search(s)
        if m is not None:
            gv = m.group()
            if s not in self.ptc.dayOffsets:

                if (gv != s):
                    # capture remaining string
                    parseStr = gv
                    chunk1 = s[:m.start()]
                    chunk2 = s[m.end():]
                    s = '%s %s' % (chunk1, chunk2)
                else:
                    parseStr = s
                    s = ''

        if parseStr and not ctx.hasDate:
            debug and log.debug(
                'found (weekday) [%s][%s][%s]', parseStr, chunk1, chunk2)
            sourceTime = self._evalWeekday(parseStr, sourceTime)

        return s, sourceTime, bool(parseStr)

    def _partialParseTimeStr(self, s, sourceTime):
        """
        test if giving C{s} matched CRE_TIME, used by L{parse()}

        @type  s:          string
        @param s:          date/time text to evaluate
        @type  sourceTime: struct_time
        @param sourceTime: C{struct_time} value to use as the base

        @rtype:  tuple
        @return: tuple of remained date/time text, datetime object and
                 an boolean value to describ if matched or not

        """
        parseStr = None
        chunk1 = chunk2 = ''

        # Natural language time strings
        m = self.ptc.CRE_TIME.search(s)
        if m is not None or s in self.ptc.re_values['now']:

            if (m and m.group() != s):
                # capture remaining string
                parseStr = m.group()
                chunk1 = s[:m.start()]
                chunk2 = s[m.end():]
                s = '%s %s' % (chunk1, chunk2)
            else:
                parseStr = s
                s = ''

        if parseStr:
            debug and log.debug(
                'found (time) [%s][%s][%s]', parseStr, chunk1, chunk2)
            sourceTime = self._evalTimeStr(parseStr, sourceTime)

        return s, sourceTime, bool(parseStr)

    def _partialParseMeridian(self, s, sourceTime):
        """
        test if giving C{s} matched CRE_TIMEHMS2, used by L{parse()}

        @type  s:          string
        @param s:          date/time text to evaluate
        @type  sourceTime: struct_time
        @param sourceTime: C{struct_time} value to use as the base

        @rtype:  tuple
        @return: tuple of remained date/time text, datetime object and
                 an boolean value to describ if matched or not

        """
        parseStr = None
        chunk1 = chunk2 = ''

        # HH:MM(:SS) am/pm time strings
        m = self.ptc.CRE_TIMEHMS2.search(s)
        if m is not None:

            if m.group('minutes') is not None:
                if m.group('seconds') is not None:
                    parseStr = '%s:%s:%s' % (m.group('hours'),
                                             m.group('minutes'),
                                             m.group('seconds'))
                else:
                    parseStr = '%s:%s' % (m.group('hours'),
                                          m.group('minutes'))
            else:
                parseStr = m.group('hours')
            parseStr += ' ' + m.group('meridian')

            chunk1 = s[:m.start()]
            chunk2 = s[m.end():]

            s = '%s %s' % (chunk1, chunk2)

        if parseStr:
            debug and log.debug('found (meridian) [%s][%s][%s]',
                                parseStr, chunk1, chunk2)
            sourceTime = self._evalMeridian(parseStr, sourceTime)

        return s, sourceTime, bool(parseStr)

    def _partialParseTimeStd(self, s, sourceTime):
        """
        test if giving C{s} matched CRE_TIMEHMS, used by L{parse()}

        @type  s:          string
        @param s:          date/time text to evaluate
        @type  sourceTime: struct_time
        @param sourceTime: C{struct_time} value to use as the base

        @rtype:  tuple
        @return: tuple of remained date/time text, datetime object and
                 an boolean value to describ if matched or not

        """
        parseStr = None
        chunk1 = chunk2 = ''

        # HH:MM(:SS) time strings
        m = self.ptc.CRE_TIMEHMS.search(s)
        if m is not None:

            if m.group('seconds') is not None:
                parseStr = '%s:%s:%s' % (m.group('hours'),
                                         m.group('minutes'),
                                         m.group('seconds'))
                chunk1 = s[:m.start('hours')]
                chunk2 = s[m.end('seconds'):]
            else:
                parseStr = '%s:%s' % (m.group('hours'),
                                      m.group('minutes'))
                chunk1 = s[:m.start('hours')]
                chunk2 = s[m.end('minutes'):]

            s = '%s %s' % (chunk1, chunk2)

        if parseStr:
            debug and log.debug(
                'found (hms) [%s][%s][%s]', parseStr, chunk1, chunk2)
            sourceTime = self._evalTimeStd(parseStr, sourceTime)

        return s, sourceTime, bool(parseStr)

    def parseDT(self, datetimeString, sourceTime=None,
                tzinfo=None, version=None):
        """
        C{datetimeString} is as C{.parse}, C{sourceTime} has the same semantic
        meaning as C{.parse}, but now also accepts datetime objects.  C{tzinfo}
        accepts a tzinfo object.  It is advisable to use pytz.


        @type  datetimeString: string
        @param datetimeString: date/time text to evaluate
        @type  sourceTime:     struct_time, datetime, date, time
        @param sourceTime:     time value to use as the base
        @type  tzinfo:         tzinfo
        @param tzinfo:         Timezone to apply to generated datetime objs.
        @type  version:        integer
        @param version:        style version, default will use L{Calendar}
                               parameter version value

        @rtype:  tuple
        @return: tuple of: modified C{sourceTime} and the result flag/context

        see .parse for return code details.
        """
        # if sourceTime has a timetuple method, use thet, else, just pass the
        # entire thing to parse and prey the user knows what the hell they are
        # doing.
        sourceTime = getattr(sourceTime, 'timetuple', (lambda: sourceTime))()
        # You REALLY SHOULD be using pytz.  Using localize if available,
        # hacking if not.  Note, None is a valid tzinfo object in the case of
        # the ugly hack.
        localize = getattr(
            tzinfo,
            'localize',
            (lambda dt: dt.replace(tzinfo=tzinfo)),  # ugly hack is ugly :(
        )

        # Punt
        time_struct, ret_code = self.parse(
            datetimeString,
            sourceTime=sourceTime,
            version=version)

        # Comments from GHI indicate that it is desired to have the same return
        # signature on this method as that one it punts to, with the exception
        # of using datetime objects instead of time_structs.
        dt = localize(datetime.datetime(*time_struct[:6]))
        return dt, ret_code

    def parse(self, datetimeString, sourceTime=None, version=None):
        """
        Splits the given C{datetimeString} into tokens, finds the regex
        patterns that match and then calculates a C{struct_time} value from
        the chunks.

        If C{sourceTime} is given then the C{struct_time} value will be
        calculated from that value, otherwise from the current date/time.

        If the C{datetimeString} is parsed and date/time value found, then::

            If C{version} equals to L{VERSION_FLAG_STYLE}, the second item of
            the returned tuple will be a flag to let you know what kind of
            C{struct_time} value is being returned::

                0 = not parsed at all
                1 = parsed as a C{date}
                2 = parsed as a C{time}
                3 = parsed as a C{datetime}

            If C{version} equals to L{VERSION_CONTEXT_STYLE}, the second value
            will be an instance of L{pdtContext}

        @type  datetimeString: string
        @param datetimeString: date/time text to evaluate
        @type  sourceTime:     struct_time
        @param sourceTime:     C{struct_time} value to use as the base
        @type  version:        integer
        @param version:        style version, default will use L{Calendar}
                               parameter version value

        @rtype:  tuple
        @return: tuple of: modified C{sourceTime} and the result flag/context
        """
        debug and log.debug('parse()')

        datetimeString = re.sub(r'(\w)\.(\s)', r'\1\2', datetimeString)
        datetimeString = re.sub(r'(\w)[\'"](\s|$)', r'\1 \2', datetimeString)
        datetimeString = re.sub(r'(\s|^)[\'"](\w)', r'\1 \2', datetimeString)

        if sourceTime:
            if isinstance(sourceTime, datetime.datetime):
                debug and log.debug('coercing datetime to timetuple')
                sourceTime = sourceTime.timetuple()
            else:
                if not isinstance(sourceTime, time.struct_time) and \
                        not isinstance(sourceTime, tuple):
                    raise ValueError('sourceTime is not a struct_time')
        else:
            sourceTime = time.localtime()

        with self.context() as ctx:
            s = datetimeString.lower().strip()
            debug and log.debug('remainedString (before parsing): [%s]', s)

            while s:
                for parseMeth in (self._partialParseModifier,
                                  self._partialParseUnits,
                                  self._partialParseQUnits,
                                  self._partialParseDateStr,
                                  self._partialParseDateStd,
                                  self._partialParseDayStr,
                                  self._partialParseWeekday,
                                  self._partialParseTimeStr,
                                  self._partialParseMeridian,
                                  self._partialParseTimeStd):
                    retS, retTime, matched = parseMeth(s, sourceTime)
                    if matched:
                        s, sourceTime = retS.strip(), retTime
                        break
                else:
                    # nothing matched
                    s = ''

                debug and log.debug('hasDate: [%s], hasTime: [%s]',
                                    ctx.hasDate, ctx.hasTime)
                debug and log.debug('remainedString: [%s]', s)

            # String is not parsed at all
            if sourceTime is None:
                debug and log.debug('not parsed [%s]', str(sourceTime))
                sourceTime = time.localtime()

        if not isinstance(sourceTime, time.struct_time):
            sourceTime = time.struct_time(sourceTime)

        version = self.version if version is None else version
        if version == VERSION_CONTEXT_STYLE:
            return sourceTime, ctx
        else:
            return sourceTime, ctx.dateTimeFlag

    def inc(self, source, month=None, year=None):
        """
        Takes the given C{source} date, or current date if none is
        passed, and increments it according to the values passed in
        by month and/or year.

        This routine is needed because Python's C{timedelta()} function
        does not allow for month or year increments.

        @type  source: struct_time
        @param source: C{struct_time} value to increment
        @type  month:  float or integer
        @param month:  optional number of months to increment
        @type  year:   float or integer
        @param year:   optional number of years to increment

        @rtype:  datetime
        @return: C{source} incremented by the number of months and/or years
        """
        yr = source.year
        mth = source.month
        dy = source.day

        try:
            month = float(month)
        except (TypeError, ValueError):
            month = 0

        try:
            year = float(year)
        except (TypeError, ValueError):
            year = 0
        finally:
            month += year * 12
            year = 0

        subMi = 0.0
        maxDay = 0
        if month:
            mi = int(month)
            subMi = month - mi

            y = int(mi / 12.0)
            m = mi - y * 12

            mth = mth + m
            if mth < 1:  # cross start-of-year?
                y -= 1  # yes - decrement year
                mth += 12  # and fix month
            elif mth > 12:  # cross end-of-year?
                y += 1  # yes - increment year
                mth -= 12  # and fix month

            yr += y

            # if the day ends up past the last day of
            # the new month, set it to the last day
            maxDay = self.ptc.daysInMonth(mth, yr)
            if dy > maxDay:
                dy = maxDay

        if yr > datetime.MAXYEAR or yr < datetime.MINYEAR:
            raise OverflowError('year is out of range')

        d = source.replace(year=yr, month=mth, day=dy)
        if subMi:
            d += datetime.timedelta(days=subMi * maxDay)
        return source + (d - source)

    def nlp(self, inputString, sourceTime=None, version=None):
        """Utilizes parse() after making judgements about what datetime
        information belongs together.

        It makes logical groupings based on proximity and returns a parsed
        datetime for each matched grouping of datetime text, along with
        location info within the given inputString.

        @type  inputString: string
        @param inputString: natural language text to evaluate
        @type  sourceTime:  struct_time
        @param sourceTime:  C{struct_time} value to use as the base
        @type  version:     integer
        @param version:     style version, default will use L{Calendar}
                            parameter version value

        @rtype:  tuple or None
        @return: tuple of tuples in the format (parsed_datetime as
                 datetime.datetime, flags as int, start_pos as int,
                 end_pos as int, matched_text as string) or None if there
                 were no matches
        """

        orig_inputstring = inputString

        # replace periods at the end of sentences w/ spaces
        # opposed to removing them altogether in order to
        # retain relative positions (identified by alpha, period, space).
        # this is required for some of the regex patterns to match
        inputString = re.sub(r'(\w)(\.)(\s)', r'\1 \3', inputString).lower()
        inputString = re.sub(r'(\w)(\'|")(\s|$)', r'\1 \3', inputString)
        inputString = re.sub(r'(\s|^)(\'|")(\w)', r'\1 \3', inputString)

        startpos = 0  # the start position in the inputString during the loop

        # list of lists in format:
        # [startpos, endpos, matchedstring, flags, type]
        matches = []

        while startpos < len(inputString):

            # empty match
            leftmost_match = [0, 0, None, 0, None]

            # Modifier like next\prev..
            m = self.ptc.CRE_MODIFIER.search(inputString[startpos:])
            if m is not None:
                if leftmost_match[1] == 0 or \
                        leftmost_match[0] > m.start() + startpos:
                    leftmost_match[0] = m.start() + startpos
                    leftmost_match[1] = m.end() + startpos
                    leftmost_match[2] = m.group()
                    leftmost_match[3] = 0
                    leftmost_match[4] = 'modifier'

            # Quantity + Units
            m = self.ptc.CRE_UNITS.search(inputString[startpos:])
            if m is not None:
                debug and log.debug('CRE_UNITS matched')
                if self._UnitsTrapped(inputString[startpos:], m, 'units'):
                    debug and log.debug('day suffix trapped by unit match')
                else:

                    if leftmost_match[1] == 0 or \
                            leftmost_match[0] > m.start('qty') + startpos:
                        leftmost_match[0] = m.start('qty') + startpos
                        leftmost_match[1] = m.end('qty') + startpos
                        leftmost_match[2] = m.group('qty')
                        leftmost_match[3] = 3
                        leftmost_match[4] = 'units'

                        if m.start('qty') > 0 and \
                                inputString[m.start('qty') - 1] == '-':
                            leftmost_match[0] = leftmost_match[0] - 1
                            leftmost_match[2] = '-' + leftmost_match[2]

            # Quantity + Units
            m = self.ptc.CRE_QUNITS.search(inputString[startpos:])
            if m is not None:
                debug and log.debug('CRE_QUNITS matched')
                if self._UnitsTrapped(inputString[startpos:], m, 'qunits'):
                    debug and log.debug('day suffix trapped by qunit match')
                else:
                    if leftmost_match[1] == 0 or \
                            leftmost_match[0] > m.start('qty') + startpos:
                        leftmost_match[0] = m.start('qty') + startpos
                        leftmost_match[1] = m.end('qty') + startpos
                        leftmost_match[2] = m.group('qty')
                        leftmost_match[3] = 3
                        leftmost_match[4] = 'qunits'

                        if m.start('qty') > 0 and \
                                inputString[m.start('qty') - 1] == '-':
                            leftmost_match[0] = leftmost_match[0] - 1
                            leftmost_match[2] = '-' + leftmost_match[2]

            m = self.ptc.CRE_DATE3.search(inputString[startpos:])
            # NO LONGER NEEDED, THE REGEXP HANDLED MTHNAME NOW
            # for match in self.ptc.CRE_DATE3.finditer(inputString[startpos:]):
            # to prevent "HH:MM(:SS) time strings" expressions from
            # triggering this regex, we checks if the month field exists
            # in the searched expression, if it doesn't exist, the date
            # field is not valid
            #     if match.group('mthname'):
            #         m = self.ptc.CRE_DATE3.search(inputString[startpos:],
            #                                       match.start())
            #         break

            # String date format
            if m is not None:
                if leftmost_match[1] == 0 or \
                        leftmost_match[0] > m.start('date') + startpos:
                    leftmost_match[0] = m.start('date') + startpos
                    leftmost_match[1] = m.end('date') + startpos
                    leftmost_match[2] = m.group('date')
                    leftmost_match[3] = 1
                    leftmost_match[4] = 'dateStr'

            # Standard date format
            m = self.ptc.CRE_DATE.search(inputString[startpos:])
            if m is not None:
                if leftmost_match[1] == 0 or \
                        leftmost_match[0] > m.start('date') + startpos:
                    leftmost_match[0] = m.start('date') + startpos
                    leftmost_match[1] = m.end('date') + startpos
                    leftmost_match[2] = m.group('date')
                    leftmost_match[3] = 1
                    leftmost_match[4] = 'dateStd'

            # Natural language day strings
            m = self.ptc.CRE_DAY.search(inputString[startpos:])
            if m is not None:
                if leftmost_match[1] == 0 or \
                        leftmost_match[0] > m.start() + startpos:
                    leftmost_match[0] = m.start() + startpos
                    leftmost_match[1] = m.end() + startpos
                    leftmost_match[2] = m.group()
                    leftmost_match[3] = 1
                    leftmost_match[4] = 'dayStr'

            # Weekday
            m = self.ptc.CRE_WEEKDAY.search(inputString[startpos:])
            if m is not None:
                if inputString[startpos:] not in self.ptc.dayOffsets:
                    if leftmost_match[1] == 0 or \
                            leftmost_match[0] > m.start() + startpos:
                        leftmost_match[0] = m.start() + startpos
                        leftmost_match[1] = m.end() + startpos
                        leftmost_match[2] = m.group()
                        leftmost_match[3] = 1
                        leftmost_match[4] = 'weekdy'

            # Natural language time strings
            m = self.ptc.CRE_TIME.search(inputString[startpos:])
            if m is not None:
                if leftmost_match[1] == 0 or \
                        leftmost_match[0] > m.start() + startpos:
                    leftmost_match[0] = m.start() + startpos
                    leftmost_match[1] = m.end() + startpos
                    leftmost_match[2] = m.group()
                    leftmost_match[3] = 2
                    leftmost_match[4] = 'timeStr'

            # HH:MM(:SS) am/pm time strings
            m = self.ptc.CRE_TIMEHMS2.search(inputString[startpos:])
            if m is not None:
                if leftmost_match[1] == 0 or \
                        leftmost_match[0] > m.start('hours') + startpos:
                    leftmost_match[0] = m.start('hours') + startpos
                    leftmost_match[1] = m.end('meridian') + startpos
                    leftmost_match[2] = inputString[leftmost_match[0]:
                                                    leftmost_match[1]]
                    leftmost_match[3] = 2
                    leftmost_match[4] = 'meridian'

            # HH:MM(:SS) time strings
            m = self.ptc.CRE_TIMEHMS.search(inputString[startpos:])
            if m is not None:
                if leftmost_match[1] == 0 or \
                        leftmost_match[0] > m.start('hours') + startpos:
                    leftmost_match[0] = m.start('hours') + startpos
                    if m.group('seconds') is not None:
                        leftmost_match[1] = m.end('seconds') + startpos
                    else:
                        leftmost_match[1] = m.end('minutes') + startpos
                    leftmost_match[2] = inputString[leftmost_match[0]:
                                                    leftmost_match[1]]
                    leftmost_match[3] = 2
                    leftmost_match[4] = 'timeStd'

            # Units only; must be preceded by a modifier
            if len(matches) > 0 and matches[-1][3] == 0:
                m = self.ptc.CRE_UNITS_ONLY.search(inputString[startpos:])
                # Ensure that any match is immediately proceded by the
                # modifier. "Next is the word 'month'" should not parse as a
                # date while "next month" should
                if m is not None and \
                        inputString[startpos:startpos +
                                    m.start()].strip() == '':
                    debug and log.debug('CRE_UNITS_ONLY matched [%s]',
                                        m.group())
                    if leftmost_match[1] == 0 or \
                            leftmost_match[0] > m.start() + startpos:
                        leftmost_match[0] = m.start() + startpos
                        leftmost_match[1] = m.end() + startpos
                        leftmost_match[2] = m.group()
                        leftmost_match[3] = 3
                        leftmost_match[4] = 'unitsOnly'

            # set the start position to the end pos of the leftmost match
            startpos = leftmost_match[1]

            # nothing was detected
            # so break out of the loop
            if startpos == 0:
                startpos = len(inputString)
            else:
                if leftmost_match[3] > 0:
                    m = self.ptc.CRE_NLP_PREFIX.search(
                        inputString[:leftmost_match[0]] +
                        ' ' + str(leftmost_match[3]))
                    if m is not None:
                        leftmost_match[0] = m.start('nlp_prefix')
                        leftmost_match[2] = inputString[leftmost_match[0]:
                                                        leftmost_match[1]]
                matches.append(leftmost_match)

        # find matches in proximity with one another and
        # return all the parsed values
        proximity_matches = []
        if len(matches) > 1:
            combined = ''
            from_match_index = 0
            date = matches[0][3] == 1
            time = matches[0][3] == 2
            units = matches[0][3] == 3
            for i in range(1, len(matches)):

                # test proximity (are there characters between matches?)
                endofprevious = matches[i - 1][1]
                begofcurrent = matches[i][0]
                if orig_inputstring[endofprevious:
                                    begofcurrent].lower().strip() != '':
                    # this one isn't in proximity, but maybe
                    # we have enough to make a datetime
                    # TODO: make sure the combination of
                    # formats (modifier, dateStd, etc) makes logical sense
                    # before parsing together
                    if date or time or units:
                        combined = orig_inputstring[matches[from_match_index]
                                                    [0]:matches[i - 1][1]]
                        parsed_datetime, flags = self.parse(combined,
                                                            sourceTime,
                                                            version)
                        proximity_matches.append((
                            datetime.datetime(*parsed_datetime[:6]),
                            flags,
                            matches[from_match_index][0],
                            matches[i - 1][1],
                            combined))
                    # not in proximity, reset starting from current
                    from_match_index = i
                    date = matches[i][3] == 1
                    time = matches[i][3] == 2
                    units = matches[i][3] == 3
                    continue
                else:
                    if matches[i][3] == 1:
                        date = True
                    if matches[i][3] == 2:
                        time = True
                    if matches[i][3] == 3:
                        units = True

            # check last
            # we have enough to make a datetime
            if date or time or units:
                combined = orig_inputstring[matches[from_match_index][0]:
                                            matches[len(matches) - 1][1]]
                parsed_datetime, flags = self.parse(combined, sourceTime,
                                                    version)
                proximity_matches.append((
                    datetime.datetime(*parsed_datetime[:6]),
                    flags,
                    matches[from_match_index][0],
                    matches[len(matches) - 1][1],
                    combined))

        elif len(matches) == 0:
            return None
        else:
            if matches[0][3] == 0:  # not enough info to parse
                return None
            else:
                combined = orig_inputstring[matches[0][0]:matches[0][1]]
                parsed_datetime, flags = self.parse(matches[0][2], sourceTime,
                                                    version)
                proximity_matches.append((
                    datetime.datetime(*parsed_datetime[:6]),
                    flags,
                    matches[0][0],
                    matches[0][1],
                    combined))

        return tuple(proximity_matches)


def _initSymbols(ptc):
    """
    Initialize symbols and single character constants.
    """
    # build am and pm lists to contain
    # original case, lowercase, first-char and dotted
    # versions of the meridian text
    ptc.am = ['', '']
    ptc.pm = ['', '']
    for idx, xm in enumerate(ptc.locale.meridian[:2]):
        # 0: am
        # 1: pm
        target = ['am', 'pm'][idx]
        setattr(ptc, target, [xm])
        target = getattr(ptc, target)
        if xm:
            lxm = xm.lower()
            target.extend((xm[0], '{0}.{1}.'.format(*xm),
                           lxm, lxm[0], '{0}.{1}.'.format(*lxm)))


class Constants(object):

    """
    Default set of constants for parsedatetime.

    If PyICU is present, then the class will first try to get PyICU
    to return a locale specified by C{localeID}.  If either C{localeID} is
    None or if the locale does not exist within PyICU, then each of the
    locales defined in C{fallbackLocales} is tried in order.

    If PyICU is not present or none of the specified locales can be used,
    then the class will initialize itself to the en_US locale.

    if PyICU is not present or not requested, only the locales defined by
    C{pdtLocales} will be searched.
    """

    def __init__(self, localeID=None, usePyICU=True,
                 fallbackLocales=['en_US']):
        self.localeID = localeID
        self.fallbackLocales = fallbackLocales[:]

        if 'en_US' not in self.fallbackLocales:
            self.fallbackLocales.append('en_US')

        # define non-locale specific constants
        self.locale = None
        self.usePyICU = usePyICU

        # starting cache of leap years
        # daysInMonth will add to this if during
        # runtime it gets a request for a year not found
        self._leapYears = list(range(1904, 2097, 4))

        self.Second = 1
        self.Minute = 60  # 60 * self.Second
        self.Hour = 3600  # 60 * self.Minute
        self.Day = 86400  # 24 * self.Hour
        self.Week = 604800  # 7   * self.Day
        self.Month = 2592000  # 30  * self.Day
        self.Year = 31536000  # 365 * self.Day

        self._DaysInMonthList = (31, 28, 31, 30, 31, 30,
                                 31, 31, 30, 31, 30, 31)
        self.rangeSep = '-'
        self.BirthdayEpoch = 50

        # When True the starting time for all relative calculations will come
        # from the given SourceTime, otherwise it will be 9am

        self.StartTimeFromSourceTime = False

        # YearParseStyle controls how we parse "Jun 12", i.e. dates that do
        # not have a year present.  The default is to compare the date given
        # to the current date, and if prior, then assume the next year.
        # Setting this to 0 will prevent that.

        self.YearParseStyle = 1

        # DOWParseStyle controls how we parse "Tuesday"
        # If the current day was Thursday and the text to parse is "Tuesday"
        # then the following table shows how each style would be returned
        # -1, 0, +1
        #
        # Current day marked as ***
        #
        #          Sun Mon Tue Wed Thu Fri Sat
        # week -1
        # current         -1,0     ***
        # week +1          +1
        #
        # If the current day was Monday and the text to parse is "Tuesday"
        # then the following table shows how each style would be returned
        # -1, 0, +1
        #
        #          Sun Mon Tue Wed Thu Fri Sat
        # week -1           -1
        # current      *** 0,+1
        # week +1

        self.DOWParseStyle = 1

        # CurrentDOWParseStyle controls how we parse "Friday"
        # If the current day was Friday and the text to parse is "Friday"
        # then the following table shows how each style would be returned
        # True/False. This also depends on DOWParseStyle.
        #
        # Current day marked as ***
        #
        # DOWParseStyle = 0
        #          Sun Mon Tue Wed Thu Fri Sat
        # week -1
        # current                      T,F
        # week +1
        #
        # DOWParseStyle = -1
        #          Sun Mon Tue Wed Thu Fri Sat
        # week -1                       F
        # current                       T
        # week +1
        #
        # DOWParseStyle = +1
        #
        #          Sun Mon Tue Wed Thu Fri Sat
        # week -1
        # current                       T
        # week +1                       F

        self.CurrentDOWParseStyle = False

        if self.usePyICU:
            self.locale = get_icu(self.localeID)

            if self.locale.icu is None:
                self.usePyICU = False
                self.locale = None

        if self.locale is None:
            if self.localeID not in pdtLocales:
                for localeId in range(0, len(self.fallbackLocales)):
                    self.localeID = self.fallbackLocales[localeId]
                    if self.localeID in pdtLocales:
                        break

            self.locale = pdtLocales[self.localeID]

        if self.locale is not None:

            def _getLocaleDataAdjusted(localeData):
                """
                If localeData is defined as ["mon|mnd", 'tu|tues'...] then this
                function splits those definitions on |
                """
                adjusted = []
                for d in localeData:
                    if '|' in d:
                        adjusted += d.split("|")
                    else:
                        adjusted.append(d)
                return adjusted

            def re_join(g):
                return '|'.join(re.escape(i) for i in g)

            mths = _getLocaleDataAdjusted(self.locale.Months)
            smths = _getLocaleDataAdjusted(self.locale.shortMonths)
            swds = _getLocaleDataAdjusted(self.locale.shortWeekdays)
            wds = _getLocaleDataAdjusted(self.locale.Weekdays)

            # escape any regex special characters that may be found
            self.locale.re_values['months'] = re_join(mths)
            self.locale.re_values['shortmonths'] = re_join(smths)
            self.locale.re_values['days'] = re_join(wds)
            self.locale.re_values['shortdays'] = re_join(swds)
            self.locale.re_values['dayoffsets'] = \
                re_join(self.locale.dayOffsets)
            self.locale.re_values['numbers'] = \
                re_join(self.locale.numbers)
            self.locale.re_values['decimal_mark'] = \
                re.escape(self.locale.decimal_mark)

            units = [unit for units in self.locale.units.values()
                     for unit in units]  # flatten
            units.sort(key=len, reverse=True)  # longest first
            self.locale.re_values['units'] = re_join(units)
            self.locale.re_values['modifiers'] = re_join(self.locale.Modifiers)
            self.locale.re_values['sources'] = re_join(self.locale.re_sources)

            # For distinguishing numeric dates from times, look for timeSep
            # and meridian, if specified in the locale
            self.locale.re_values['timecomponents'] = \
                re_join(self.locale.timeSep + self.locale.meridian)

            # build weekday offsets - yes, it assumes the Weekday and
            # shortWeekday lists are in the same order and Mon..Sun
            # (Python style)
            def _buildOffsets(offsetDict, localeData, indexStart):
                o = indexStart
                for key in localeData:
                    if '|' in key:
                        for k in key.split('|'):
                            offsetDict[k] = o
                    else:
                        offsetDict[key] = o
                    o += 1

            _buildOffsets(self.locale.WeekdayOffsets,
                          self.locale.Weekdays, 0)
            _buildOffsets(self.locale.WeekdayOffsets,
                          self.locale.shortWeekdays, 0)

            # build month offsets - yes, it assumes the Months and shortMonths
            # lists are in the same order and Jan..Dec
            _buildOffsets(self.locale.MonthOffsets,
                          self.locale.Months, 1)
            _buildOffsets(self.locale.MonthOffsets,
                          self.locale.shortMonths, 1)

        _initSymbols(self)

        # TODO: add code to parse the date formats and build the regexes up
        # from sub-parts, find all hard-coded uses of date/time separators

        # not being used in code, but kept in case others are manually
        # utilizing this regex for their own purposes
        self.RE_DATE4 = r'''(?P<date>
                                (
                                    (
                                        (?P<day>\d\d?)
                                        (?P<suffix>{daysuffix})?
                                        (,)?
                                        (\s)*
                                    )
                                    (?P<mthname>
                                        \b({months}|{shortmonths})\b
                                    )\s*
                                    (?P<year>\d\d
                                        (\d\d)?
                                    )?
                                )
                            )'''.format(**self.locale.re_values)

        # still not completely sure of the behavior of the regex and
        # whether it would be best to consume all possible irrelevant
        # characters before the option groups (but within the {1,3} repetition
        # group or inside of each option group, as it currently does
        # however, right now, all tests are passing that were,
        # including fixing the bug of matching a 4-digit year as ddyy
        # when the day is absent from the string
        self.RE_DATE3 = r'''(?P<date>
                                (?:
                                    (?:^|\s+)
                                    (?P<mthname>
                                        {months}|{shortmonths}
                                    )\b
                                    |
                                    (?:^|\s+)
                                    (?P<day>[1-9]|[012]\d|3[01])
                                    (?P<suffix>{daysuffix}|)\b
                                    (?!\s*(?:{timecomponents}))
                                    |
                                    ,?\s+
                                    (?P<year>\d\d(?:\d\d|))\b
                                    (?!\s*(?:{timecomponents}))
                                ){{1,3}}
                                (?(mthname)|$-^)
                            )'''.format(**self.locale.re_values)

        # not being used in code, but kept in case others are manually
        # utilizing this regex for their own purposes
        self.RE_MONTH = r'''(\s+|^)
                            (?P<month>
                                (
                                    (?P<mthname>
                                        \b({months}|{shortmonths})\b
                                    )
                                    (\s*
                                        (?P<year>(\d{{4}}))
                                    )?
                                )
                            )
                            (?=\s+|$|[^\w])'''.format(**self.locale.re_values)

        self.RE_WEEKDAY = r'''\b
                              (?:
                                  {days}|{shortdays}
                              )
                              \b'''.format(**self.locale.re_values)

        self.RE_NUMBER = (r'(\b(?:{numbers})\b|\d+(?:{decimal_mark}\d+|))'
                          .format(**self.locale.re_values))

        self.RE_SPECIAL = (r'(?P<special>^[{specials}]+)\s+'
                           .format(**self.locale.re_values))

        self.RE_UNITS_ONLY = (r'''\b({units})\b'''
                              .format(**self.locale.re_values))

        self.RE_UNITS = r'''\b(?P<qty>
                                -?
                                (?:\d+(?:{decimal_mark}\d+|)|(?:{numbers})\b)\s*
                                (?P<units>{units})
                            )\b'''.format(**self.locale.re_values)

        self.RE_QUNITS = r'''\b(?P<qty>
                                 -?
                                 (?:\d+(?:{decimal_mark}\d+|)|(?:{numbers})\s+)\s*
                                 (?P<qunits>{qunits})
                             )\b'''.format(**self.locale.re_values)

        self.RE_MODIFIER = r'''\b(?:
                                   {modifiers}
                               )\b'''.format(**self.locale.re_values)

        self.RE_TIMEHMS = r'''([\s(\["'-]|^)
                              (?P<hours>\d\d?)
                              (?P<tsep>{timeseparator}|)
                              (?P<minutes>\d\d)
                              (?:(?P=tsep)
                                  (?P<seconds>\d\d
                                      (?:[\.,]\d+)?
                                  )
                              )?\b'''.format(**self.locale.re_values)

        self.RE_TIMEHMS2 = r'''([\s(\["'-]|^)
                               (?P<hours>\d\d?)
                               (?:
                                   (?P<tsep>{timeseparator}|)
                                   (?P<minutes>\d\d?)
                                   (?:(?P=tsep)
                                       (?P<seconds>\d\d?
                                           (?:[\.,]\d+)?
                                       )
                                   )?
                               )?'''.format(**self.locale.re_values)

        # 1, 2, and 3 here refer to the type of match date, time, or units
        self.RE_NLP_PREFIX = r'''\b(?P<nlp_prefix>
                                  (on)
                                  (\s)+1
                                  |
                                  (at|in)
                                  (\s)+2
                                  |
                                  (in)
                                  (\s)+3
                                 )'''

        if 'meridian' in self.locale.re_values:
            self.RE_TIMEHMS2 += (r'\s*(?P<meridian>{meridian})\b'
                                 .format(**self.locale.re_values))
        else:
            self.RE_TIMEHMS2 += r'\b'

        # Always support common . and - separators
        dateSeps = ''.join(re.escape(s)
                           for s in self.locale.dateSep + ['-', '.'])

        self.RE_DATE = r'''([\s(\["'-]|^)
                           (?P<date>
                                \d\d?[{0}]\d\d?(?:[{0}]\d\d(?:\d\d)?)?
                                |
                                \d{{4}}[{0}]\d\d?[{0}]\d\d?
                            )
                           \b'''.format(dateSeps)

        self.RE_DATE2 = r'[{0}]'.format(dateSeps)

        assert 'dayoffsets' in self.locale.re_values

        self.RE_DAY = r'''\b
                          (?:
                              {dayoffsets}
                          )
                          \b'''.format(**self.locale.re_values)

        self.RE_DAY2 = r'''(?P<day>\d\d?)
                           (?P<suffix>{daysuffix})?
                       '''.format(**self.locale.re_values)

        self.RE_TIME = r'''\b
                           (?:
                               {sources}
                           )
                           \b'''.format(**self.locale.re_values)

        self.RE_REMAINING = r'\s+'

        # Regex for date/time ranges
        self.RE_RTIMEHMS = r'''(\s*|^)
                               (\d\d?){timeseparator}
                               (\d\d)
                               ({timeseparator}(\d\d))?
                               (\s*|$)'''.format(**self.locale.re_values)

        self.RE_RTIMEHMS2 = (r'''(\s*|^)
                                 (\d\d?)
                                 ({timeseparator}(\d\d?))?
                                 ({timeseparator}(\d\d?))?'''
                             .format(**self.locale.re_values))

        if 'meridian' in self.locale.re_values:
            self.RE_RTIMEHMS2 += (r'\s*({meridian})'
                                  .format(**self.locale.re_values))

        self.RE_RDATE = r'(\d+([%s]\d+)+)' % dateSeps
        self.RE_RDATE3 = r'''(
                                (
                                    (
                                        \b({months})\b
                                    )\s*
                                    (
                                        (\d\d?)
                                        (\s?|{daysuffix}|$)+
                                    )?
                                    (,\s*\d{{4}})?
                                )
                            )'''.format(**self.locale.re_values)

        # "06/07/06 - 08/09/06"
        self.DATERNG1 = (r'{0}\s*{rangeseparator}\s*{0}'
                         .format(self.RE_RDATE, **self.locale.re_values))

        # "march 31 - june 1st, 2006"
        self.DATERNG2 = (r'{0}\s*{rangeseparator}\s*{0}'
                         .format(self.RE_RDATE3, **self.locale.re_values))

        # "march 1rd -13th"
        self.DATERNG3 = (r'{0}\s*{rangeseparator}\s*(\d\d?)\s*(rd|st|nd|th)?'
                         .format(self.RE_RDATE3, **self.locale.re_values))

        # "4:00:55 pm - 5:90:44 am", '4p-5p'
        self.TIMERNG1 = (r'{0}\s*{rangeseparator}\s*{0}'
                         .format(self.RE_RTIMEHMS2, **self.locale.re_values))

        self.TIMERNG2 = (r'{0}\s*{rangeseparator}\s*{0}'
                         .format(self.RE_RTIMEHMS, **self.locale.re_values))

        # "4-5pm "
        self.TIMERNG3 = (r'\d\d?\s*{rangeseparator}\s*{0}'
                         .format(self.RE_RTIMEHMS2, **self.locale.re_values))

        # "4:30-5pm "
        self.TIMERNG4 = (r'{0}\s*{rangeseparator}\s*{1}'
                         .format(self.RE_RTIMEHMS, self.RE_RTIMEHMS2,
                                 **self.locale.re_values))

        self.re_option = re.IGNORECASE + re.VERBOSE
        self.cre_source = {'CRE_SPECIAL': self.RE_SPECIAL,
                           'CRE_NUMBER': self.RE_NUMBER,
                           'CRE_UNITS': self.RE_UNITS,
                           'CRE_UNITS_ONLY': self.RE_UNITS_ONLY,
                           'CRE_QUNITS': self.RE_QUNITS,
                           'CRE_MODIFIER': self.RE_MODIFIER,
                           'CRE_TIMEHMS': self.RE_TIMEHMS,
                           'CRE_TIMEHMS2': self.RE_TIMEHMS2,
                           'CRE_DATE': self.RE_DATE,
                           'CRE_DATE2': self.RE_DATE2,
                           'CRE_DATE3': self.RE_DATE3,
                           'CRE_DATE4': self.RE_DATE4,
                           'CRE_MONTH': self.RE_MONTH,
                           'CRE_WEEKDAY': self.RE_WEEKDAY,
                           'CRE_DAY': self.RE_DAY,
                           'CRE_DAY2': self.RE_DAY2,
                           'CRE_TIME': self.RE_TIME,
                           'CRE_REMAINING': self.RE_REMAINING,
                           'CRE_RTIMEHMS': self.RE_RTIMEHMS,
                           'CRE_RTIMEHMS2': self.RE_RTIMEHMS2,
                           'CRE_RDATE': self.RE_RDATE,
                           'CRE_RDATE3': self.RE_RDATE3,
                           'CRE_TIMERNG1': self.TIMERNG1,
                           'CRE_TIMERNG2': self.TIMERNG2,
                           'CRE_TIMERNG3': self.TIMERNG3,
                           'CRE_TIMERNG4': self.TIMERNG4,
                           'CRE_DATERNG1': self.DATERNG1,
                           'CRE_DATERNG2': self.DATERNG2,
                           'CRE_DATERNG3': self.DATERNG3,
                           'CRE_NLP_PREFIX': self.RE_NLP_PREFIX}
        self.cre_keys = set(self.cre_source.keys())

    def __getattr__(self, name):
        if name in self.cre_keys:
            value = re.compile(self.cre_source[name], self.re_option)
            setattr(self, name, value)
            return value
        elif name in self.locale.locale_keys:
            return getattr(self.locale, name)
        else:
            raise AttributeError(name)

    def daysInMonth(self, month, year):
        """
        Take the given month (1-12) and a given year (4 digit) return
        the number of days in the month adjusting for leap year as needed
        """
        result = None
        debug and log.debug('daysInMonth(%s, %s)', month, year)
        if month > 0 and month <= 12:
            result = self._DaysInMonthList[month - 1]

            if month == 2:
                if year in self._leapYears:
                    result += 1
                else:
                    if calendar.isleap(year):
                        self._leapYears.append(year)
                        result += 1

        return result

    def getSource(self, sourceKey, sourceTime=None):
        """
        GetReturn a date/time tuple based on the giving source key
        and the corresponding key found in self.re_sources.

        The current time is used as the default and any specified
        item found in self.re_sources is inserted into the value
        and the generated dictionary is returned.
        """
        if sourceKey not in self.re_sources:
            return None

        if sourceTime is None:
            (yr, mth, dy, hr, mn, sec, wd, yd, isdst) = time.localtime()
        else:
            (yr, mth, dy, hr, mn, sec, wd, yd, isdst) = sourceTime

        defaults = {'yr': yr, 'mth': mth, 'dy': dy,
                    'hr': hr, 'mn': mn, 'sec': sec}

        source = self.re_sources[sourceKey]

        values = {}

        for key, default in defaults.items():
            values[key] = source.get(key, default)

        return (values['yr'], values['mth'], values['dy'],
                values['hr'], values['mn'], values['sec'],
                wd, yd, isdst)
