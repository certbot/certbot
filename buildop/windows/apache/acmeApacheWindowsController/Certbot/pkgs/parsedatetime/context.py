# -*- coding: utf-8 -*-
"""
parsedatetime/context.py

Context related classes

"""

from threading import local


class pdtContextStack(object):
    """
    A thread-safe stack to store context(s)

    Internally used by L{Calendar} object
    """

    def __init__(self):
        self.__local = local()

    @property
    def __stack(self):
        if not hasattr(self.__local, 'stack'):
            self.__local.stack = []
        return self.__local.stack

    def push(self, ctx):
        self.__stack.append(ctx)

    def pop(self):
        try:
            return self.__stack.pop()
        except IndexError:
            return None

    def last(self):
        try:
            return self.__stack[-1]
        except IndexError:
            raise RuntimeError('context stack is empty')

    def isEmpty(self):
        return not self.__stack


class pdtContext(object):
    """
    Context contains accuracy flag detected by L{Calendar.parse()}

    Accuracy flag uses bitwise-OR operation and is combined by:

        ACU_YEAR - "next year", "2014"
        ACU_MONTH - "March", "July 2014"
        ACU_WEEK - "last week", "next 3 weeks"
        ACU_DAY - "tomorrow", "July 4th 2014"
        ACU_HALFDAY - "morning", "tonight"
        ACU_HOUR - "18:00", "next hour"
        ACU_MIN - "18:32", "next 10 minutes"
        ACU_SEC - "18:32:55"
        ACU_NOW - "now"

    """

    __slots__ = ('accuracy',)

    ACU_YEAR = 2 ** 0
    ACU_MONTH = 2 ** 1
    ACU_WEEK = 2 ** 2
    ACU_DAY = 2 ** 3
    ACU_HALFDAY = 2 ** 4
    ACU_HOUR = 2 ** 5
    ACU_MIN = 2 ** 6
    ACU_SEC = 2 ** 7
    ACU_NOW = 2 ** 8

    ACU_DATE = ACU_YEAR | ACU_MONTH | ACU_WEEK | ACU_DAY
    ACU_TIME = ACU_HALFDAY | ACU_HOUR | ACU_MIN | ACU_SEC | ACU_NOW

    _ACCURACY_MAPPING = [
        (ACU_YEAR, 'year'),
        (ACU_MONTH, 'month'),
        (ACU_WEEK, 'week'),
        (ACU_DAY, 'day'),
        (ACU_HALFDAY, 'halfday'),
        (ACU_HOUR, 'hour'),
        (ACU_MIN, 'min'),
        (ACU_SEC, 'sec'),
        (ACU_NOW, 'now')]

    _ACCURACY_REVERSE_MAPPING = {
        'year': ACU_YEAR,
        'years': ACU_YEAR,
        'month': ACU_MONTH,
        'months': ACU_MONTH,
        'week': ACU_WEEK,
        'weeks': ACU_WEEK,
        'day': ACU_DAY,
        'days': ACU_DAY,
        'halfday': ACU_HALFDAY,
        'morning': ACU_HALFDAY,
        'afternoon': ACU_HALFDAY,
        'evening': ACU_HALFDAY,
        'night': ACU_HALFDAY,
        'tonight': ACU_HALFDAY,
        'midnight': ACU_HALFDAY,
        'hour': ACU_HOUR,
        'hours': ACU_HOUR,
        'min': ACU_MIN,
        'minute': ACU_MIN,
        'mins': ACU_MIN,
        'minutes': ACU_MIN,
        'sec': ACU_SEC,
        'second': ACU_SEC,
        'secs': ACU_SEC,
        'seconds': ACU_SEC,
        'now': ACU_NOW}

    def __init__(self, accuracy=0):
        """
        Default constructor of L{pdtContext} class.

        @type  accuracy: integer
        @param accuracy: Accuracy flag

        @rtype:  object
        @return: L{pdtContext} instance
        """
        self.accuracy = accuracy

    def updateAccuracy(self, *accuracy):
        """
        Updates current accuracy flag
        """
        for acc in accuracy:
            if not isinstance(acc, int):
                acc = self._ACCURACY_REVERSE_MAPPING[acc]
            self.accuracy |= acc

    def update(self, context):
        """
        Uses another L{pdtContext} instance to update current one
        """
        self.updateAccuracy(context.accuracy)

    @property
    def hasDate(self):
        """
        Returns True if current context is accurate to date
        """
        return bool(self.accuracy & self.ACU_DATE)

    @property
    def hasTime(self):
        """
        Returns True if current context is accurate to time
        """
        return bool(self.accuracy & self.ACU_TIME)

    @property
    def dateTimeFlag(self):
        """
        Returns the old date/time flag code
        """
        return int(self.hasDate and 1) | int(self.hasTime and 2)

    @property
    def hasDateOrTime(self):
        """
        Returns True if current context is accurate to date/time
        """
        return bool(self.accuracy)

    def __repr__(self):
        accuracy_repr = []
        for acc, name in self._ACCURACY_MAPPING:
            if acc & self.accuracy:
                accuracy_repr.append('pdtContext.ACU_%s' % name.upper())
        if accuracy_repr:
            accuracy_repr = 'accuracy=' + ' | '.join(accuracy_repr)
        else:
            accuracy_repr = ''

        return 'pdtContext(%s)' % accuracy_repr

    def __eq__(self, ctx):
        return self.accuracy == ctx.accuracy
