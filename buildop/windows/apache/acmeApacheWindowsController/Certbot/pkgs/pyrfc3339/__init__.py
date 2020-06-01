"""
pyRFC3339 parses and generates :RFC:`3339`-compliant timestamps using Python
:class:`datetime.datetime` objects.

>>> from pyrfc3339 import generate, parse
>>> from datetime import datetime
>>> import pytz
>>> generate(datetime.utcnow().replace(tzinfo=pytz.utc)) #doctest:+ELLIPSIS
'...T...Z'
>>> parse('2009-01-01T10:01:02Z')
datetime.datetime(2009, 1, 1, 10, 1, 2, tzinfo=<UTC>)
>>> parse('2009-01-01T14:01:02-04:00')
datetime.datetime(2009, 1, 1, 14, 1, 2, tzinfo=<UTC-04:00>)

"""

from pyrfc3339.generator import generate
from pyrfc3339.parser import parse

__all__ = ['generate', 'parse']
