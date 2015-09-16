"""JOSE interfaces."""
import abc
import collections
import json

import six

from acme.jose import errors
from acme.jose import util

# pylint: disable=no-self-argument,no-method-argument,no-init,inherit-non-class
# pylint: disable=too-few-public-methods


@six.add_metaclass(abc.ABCMeta)
class JSONDeSerializable(object):
    # pylint: disable=too-few-public-methods
    """Interface for (de)serializable JSON objects.

    Please recall, that standard Python library implements
    :class:`json.JSONEncoder` and :class:`json.JSONDecoder` that perform
    translations based on respective :ref:`conversion tables
    <conversion-table>` that look pretty much like the one below (for
    complete tables see relevant Python documentation):

    .. _conversion-table:

    ======  ======
     JSON   Python
    ======  ======
    object  dict
    ...     ...
    ======  ======

    While the above **conversion table** is about translation of JSON
    documents to/from the basic Python types only,
    :class:`JSONDeSerializable` introduces the following two concepts:

      serialization
        Turning an arbitrary Python object into Python object that can
        be encoded into a JSON document. **Full serialization** produces
        a Python object composed of only basic types as required by the
        :ref:`conversion table <conversion-table>`. **Partial
        serialization** (accomplished by :meth:`to_partial_json`)
        produces a Python object that might also be built from other
        :class:`JSONDeSerializable` objects.

      deserialization
        Turning a decoded Python object (necessarily one of the basic
        types as required by the :ref:`conversion table
        <conversion-table>`) into an arbitrary Python object.

    Serialization produces **serialized object** ("partially serialized
    object" or "fully serialized object" for partial and full
    serialization respectively) and deserialization produces
    **deserialized object**, both usually denoted in the source code as
    ``jobj``.

    Wording in the official Python documentation might be confusing
    after reading the above, but in the light of those definitions, one
    can view :meth:`json.JSONDecoder.decode` as decoder and
    deserializer of basic types, :meth:`json.JSONEncoder.default` as
    serializer of basic types, :meth:`json.JSONEncoder.encode`  as
    serializer and encoder of basic types.

    One could extend :mod:`json` to support arbitrary object
    (de)serialization either by:

      - overriding :meth:`json.JSONDecoder.decode` and
        :meth:`json.JSONEncoder.default` in subclasses

      - or passing ``object_hook`` argument (or ``object_hook_pairs``)
        to :func:`json.load`/:func:`json.loads` or ``default`` argument
        for :func:`json.dump`/:func:`json.dumps`.

    Interestingly, ``default`` is required to perform only partial
    serialization, as :func:`json.dumps` applies ``default``
    recursively. This is the idea behind making :meth:`to_partial_json`
    produce only partial serialization, while providing custom
    :meth:`json_dumps` that dumps with ``default`` set to
    :meth:`json_dump_default`.

    To make further documentation a bit more concrete, please, consider
    the following imaginatory implementation example::

      class Foo(JSONDeSerializable):
          def to_partial_json(self):
              return 'foo'

          @classmethod
          def from_json(cls, jobj):
              return Foo()

      class Bar(JSONDeSerializable):
          def to_partial_json(self):
              return [Foo(), Foo()]

          @classmethod
          def from_json(cls, jobj):
              return Bar()

    """

    @abc.abstractmethod
    def to_partial_json(self):  # pragma: no cover
        """Partially serialize.

        Following the example, **partial serialization** means the following::

          assert isinstance(Bar().to_partial_json()[0], Foo)
          assert isinstance(Bar().to_partial_json()[1], Foo)

          # in particular...
          assert Bar().to_partial_json() != ['foo', 'foo']

        :raises acme.jose.errors.SerializationError:
            in case of any serialization error.
        :returns: Partially serializable object.

        """
        raise NotImplementedError()

    def to_json(self):
        """Fully serialize.

        Again, following the example from before, **full serialization**
        means the following::

          assert Bar().to_json() == ['foo', 'foo']

        :raises acme.jose.errors.SerializationError:
            in case of any serialization error.
        :returns: Fully serialized object.

        """
        def _serialize(obj):
            if isinstance(obj, JSONDeSerializable):
                return _serialize(obj.to_partial_json())
            if isinstance(obj, six.string_types):  # strings are Sequence
                return obj
            elif isinstance(obj, list):
                return [_serialize(subobj) for subobj in obj]
            elif isinstance(obj, collections.Sequence):
                # default to tuple, otherwise Mapping could get
                # unhashable list
                return tuple(_serialize(subobj) for subobj in obj)
            elif isinstance(obj, collections.Mapping):
                return dict((_serialize(key), _serialize(value))
                            for key, value in six.iteritems(obj))
            else:
                return obj

        return _serialize(self)

    @util.abstractclassmethod
    def from_json(cls, jobj):  # pylint: disable=unused-argument
        """Deserialize a decoded JSON document.

        :param jobj: Python object, composed of only other basic data
            types, as decoded from JSON document. Not necessarily
            :class:`dict` (as decoded from "JSON object" document).

        :raises acme.jose.errors.DeserializationError:
            if decoding was unsuccessful, e.g. in case of unparseable
            X509 certificate, or wrong padding in JOSE base64 encoded
            string, etc.

        """
        # TypeError: Can't instantiate abstract class <cls> with
        # abstract methods from_json, to_partial_json
        return cls()  # pylint: disable=abstract-class-instantiated

    @classmethod
    def json_loads(cls, json_string):
        """Deserialize from JSON document string."""
        try:
            loads = json.loads(json_string)
        except ValueError as error:
            raise errors.DeserializationError(error)
        return cls.from_json(loads)

    def json_dumps(self, **kwargs):
        """Dump to JSON string using proper serializer.

        :returns: JSON document string.
        :rtype: str

        """
        return json.dumps(self, default=self.json_dump_default, **kwargs)

    def json_dumps_pretty(self):
        """Dump the object to pretty JSON document string.

        :rtype: str

        """
        return self.json_dumps(sort_keys=True, indent=4, separators=(',', ': '))

    @classmethod
    def json_dump_default(cls, python_object):
        """Serialize Python object.

        This function is meant to be passed as ``default`` to
        :func:`json.dump` or :func:`json.dumps`. They call
        ``default(python_object)`` only for non-basic Python types, so
        this function necessarily raises :class:`TypeError` if
        ``python_object`` is not an instance of
        :class:`IJSONSerializable`.

        Please read the class docstring for more information.

        """
        if isinstance(python_object, JSONDeSerializable):
            return python_object.to_partial_json()
        else:  # this branch is necessary, cannot just "return"
            raise TypeError(repr(python_object) + ' is not JSON serializable')
