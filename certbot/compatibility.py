"""Functions for dealing with Python 2/3 compatibility."""
import six

def python_2_unicode_compatible(cls):
    """ Used as a decorator on classes that define __str__ for Python2/3 compatibility
    and dealing with UTF-8.

    Originally under the BSD license, which is compatible with the Apache license.
    TODO: check this ^
    """
    # Yes, python_2_unicode_compatible ships with newer versions of six (>1.9.0), but 
    # we don't want to break things for those running older versions.
    if six.PY2:
        if '__str__' not in cls.__dict__:
            raise ValueError("@python_2_unicode_compatible cannot be applied "
                    "to %s because it doesn't define __str__()." %
                    cls.__name__)
        cls.__unicode__ = cls.__str__
        cls.__str__ = lambda self: self.__unicode__().encode('utf-8')
    return cls



