from typing import Any, Optional
import sys

if sys.version_info[0] >= 3:
    from io import BytesIO
    from urllib.parse import quote_from_bytes as url_quote
else:
    from cStringIO import StringIO as BytesIO
    from urllib import quote as url_quote

PY2: Any
PYPY: Any
unichr: Any
range_type: Any
text_type: Any
string_types: Any
integer_types: Any
iterkeys: Any
itervalues: Any
iteritems: Any
NativeStringIO: Any

def reraise(tp, value, tb: Optional[Any] = ...): ...

ifilter: Any
imap: Any
izip: Any
intern: Any
implements_iterator: Any
implements_to_string: Any
encode_filename: Any
get_next: Any

def with_metaclass(meta, *bases): ...
