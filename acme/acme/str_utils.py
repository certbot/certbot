"""
Modified from https://github.com/zulip/zulip/blob/master/zerver/lib/str_utils.py

String Utilities:
This module helps in converting strings from one type to another.
Currently we have strings of 3 semantic types:
1.  text strings: These strings are used to represent all textual data,
    like people's names, stream names, content of messages, etc.
    These strings can contain non-ASCII characters, so its type should be
    typing.Text (which is `str` in python 3 and `unicode` in python 2).
2.  binary strings: These strings are used to represent binary data.
    This should be of type `bytes`
3.  native strings: These strings are for internal use only.  Strings of
    this type are not meant to be stored in database, displayed to end
    users, etc.  Things like exception names, parameter names, attribute
    names, etc should be native strings.  These strings should only
    contain ASCII characters and they should have type `str`.
There are 3 utility functions provided for converting strings from one type
to another - force_text, force_bytes, force_str
Interconversion between text strings and binary strings can be done by
using encode and decode appropriately or by using the utility functions
force_text and force_bytes.
It is recommended to use the utility functions for other string conversions.
"""
import six
from magic_typing import Union, Text # pylint: disable=unused-import


def force_text(s, encoding='utf-8'):
    # (Union[Text, bytes], str) -> Text
    """converts a string to a unicode text string
       use this when reading in data
    """
    if isinstance(s, six.text_type):
        return s
    elif isinstance(s, bytes):
        return s.decode(encoding)
    else:
        raise TypeError("force_text expects a string type")

def force_bytes(s, encoding='utf-8'):
    # (Union[Text, bytes], str) -> bytes
    """converts a string to binary string
       use this when sending out some data"""
    if isinstance(s, bytes):
        return s
    elif isinstance(s, six.text_type):
        return s.encode(encoding)
    else:
        raise TypeError("force_bytes expects a string type")

def force_str(s, encoding='utf-8'):
    # (Union[Text, bytes], str) -> str
    """converts a string to a native string
       use this when sending out some data"""
    if isinstance(s, str):
        return s
    elif isinstance(s, six.text_type):
        return s.encode(encoding)
    elif isinstance(s, bytes):
        return s.decode(encoding) # pragma: no cover
        # this is covered if we run cover using python 3, which has been done manually
        # we can't just change cover to run with python 3 because then s.encode(encoding) isn't run
    else:
        raise TypeError("force_str expects a string type")
