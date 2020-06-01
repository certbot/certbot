"""adodbapi - A python DB API 2.0 (PEP 249) interface to Microsoft ADO

Copyright (C) 2002 Henrik Ekelund, version 2.1 by Vernon Cole
* http://sourceforge.net/projects/adodbapi
"""
import sys
import time

if sys.version_info < (3,0): # in Python 2, define all symbols, just like the bad old way
    from apibase import *
    VariantConversionMap = MultiMap # old name. Should use apibase.MultiMap
    from .ado_consts import *
    _makeByteBuffer = buffer
else:
    # but if the user is running Python 3, then keep the dictionary clean
    from .apibase import apilevel, threadsafety, paramstyle
    from .apibase import Warning, Error, InterfaceError, DatabaseError, DataError, OperationalError, IntegrityError
    from .apibase import InternalError, ProgrammingError, NotSupportedError, FetchFailedError
    from .apibase import NUMBER, STRING, BINARY, DATETIME, ROWID
    _makeByteBuffer = bytes

from .adodbapi import connect, Connection, __version__, dateconverter, Cursor

def Binary(aString):
    """This function constructs an object capable of holding a binary (long) string value. """
    return _makeByteBuffer(aString)

def Date(year,month,day):
    "This function constructs an object holding a date value. "
    return dateconverter.Date(year,month,day)

def Time(hour,minute,second):
    "This function constructs an object holding a time value. "
    return dateconverter.Time(hour,minute,second)

def Timestamp(year,month,day,hour,minute,second):
    "This function constructs an object holding a time stamp value. "
    return dateconverter.Timestamp(year,month,day,hour,minute,second)

def DateFromTicks(ticks):
    """This function constructs an object holding a date value from the given ticks value
    (number of seconds since the epoch; see the documentation of the standard Python time module for details). """
    return Date(*time.gmtime(ticks)[:3])

def TimeFromTicks(ticks):
    """This function constructs an object holding a time value from the given ticks value
    (number of seconds since the epoch; see the documentation of the standard Python time module for details). """
    return Time(*time.gmtime(ticks)[3:6])

def TimestampFromTicks(ticks):
    """This function constructs an object holding a time stamp value from the given
    ticks value (number of seconds since the epoch;
    see the documentation of the standard Python time module for details). """
    return Timestamp(*time.gmtime(ticks)[:6])

version = 'adodbapi v' + __version__
