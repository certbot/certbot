"""ACME utilities."""
import json
import pkg_resources

import jsonschema
import zope.interface

from letsencrypt.acme import errors
from letsencrypt.acme import interfaces


def load_schema(name):
    """Load JSON schema from distribution."""
    return json.load(open(pkg_resources.resource_filename(
        __name__, "schemata/%s.json" % name)))


class JSONDeSerializable(object):
    """JSON (de)serializable object."""
    zope.interface.implements(interfaces.IJSONSerializable)

    schema = NotImplemented

    @classmethod
    def validate_json(cls, jobj):
        """Validate JSON object against schema.

        :raises letsencrypt.acme.errors.SchemaValidationError: if object
            couldn't be validated.

        """
        try:
            jsonschema.validate(jobj, cls.schema)
        except jsonschema.ValidationError as error:
            raise errors.SchemaValidationError(error)

    @classmethod
    def from_json(cls, jobj, validate=True):
        """Deserialize from JSON.

        Note that the input ``jobj`` has not been sanitized in any way.

        :param jobj: JSON object.
        :param bool validate: Validate against schema before deserializing.
            Useful if :class:`JWK` is part of already validated json object.

        :raises letsencrypt.acme.errors.SchemaValidationError: if ``validate``
            was ``True`` and object couldn't be validated.

        :returns: instance of the class

        """
        if validate:
            cls.validate_json(jobj)
        return cls._from_valid_json(jobj)

    @classmethod
    def _from_valid_json(cls, jobj):
        """Deserializa from valid JSON object.

        :param jobj: JSON object that has been validated against schema.

        """
        raise NotImplementedError()

    @classmethod
    def json_loads(cls, json_string, validate=True):
        """Load JSON string."""
        return cls.from_json(json.loads(json_string), validate)

    def to_json(self):
        """Prepare JSON serializable object."""
        raise NotImplementedError()

    def json_dumps(self):
        """Dump to JSON string using proper serializer.

        :returns: JSON serialized string.
        :rtype: str

        """
        return json.dumps(self, default=dump_ijsonserializable)


def dump_ijsonserializable(python_object):
    """Serialize IJSONSerializable to JSON.

    This is meant to be passed to :func:`json.dumps` as ``default``
    argument.

    """
    if interfaces.IJSONSerializable.providedBy(python_object):
        return python_object.to_json()
    else:
        raise TypeError(repr(python_object) + ' is not JSON serializable')


class ImmutableMap(object):  # pylint: disable=too-few-public-methods
    """Immutable key to value mapping with attribute access."""

    __slots__ = ()
    """Must be overriden in subclasses."""

    def __init__(self, **kwargs):
        if set(kwargs) != set(self.__slots__):
            raise TypeError(
                '__init__() takes exactly the following arguments: {0} '
                '({1} given)'.format(', '.join(self.__slots__),
                                     ', '.join(kwargs) if kwargs else 'none'))
        for slot in self.__slots__:
            object.__setattr__(self, slot, kwargs.pop(slot))

    def __setattr__(self, name, value):
        raise AttributeError("can't set attribute")

    def __eq__(self, other):
        return isinstance(other, self.__class__) and all(
            getattr(self, slot) == getattr(other, slot)
            for slot in self.__slots__)

    def __hash__(self):
        return hash(tuple(getattr(self, slot) for slot in self.__slots__))

    def __repr__(self):
        return '{0}({1})'.format(self.__class__.__name__, ', '.join(
            '{0}={1}'.format(slot, getattr(self, slot))
            for slot in self.__slots__))
