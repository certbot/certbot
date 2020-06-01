"""ACME utilities."""
import six


def map_keys(dikt, func):
    """Map dictionary keys."""
    return dict((func(key), value) for key, value in six.iteritems(dikt))
