"""ACME utilities."""
from letsencrypt.acme import interfaces


def dump_ijsonserializable(python_object):
    """Serialize IJSONSerializable to JSON.

    This is meant to be passed to :func:`json.dumps` as ``default``
    argument.

    """
    if interfaces.IJSONSerializable.providedBy(python_object):
        return python_object.to_json()
    else:
        raise TypeError(repr(python_object) + ' is not JSON serializable')
