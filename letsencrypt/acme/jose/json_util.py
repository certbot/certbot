"""JSON (de)serialization framework.

The framework presented here is somewhat based on `Go's "json" package`_
(especially the ``omitempty`` functionality).

.. _`Go's "json" package`: http://golang.org/pkg/encoding/json/

"""
import abc
import binascii
import logging

import M2Crypto

from letsencrypt.acme.jose import b64
from letsencrypt.acme.jose import errors
from letsencrypt.acme.jose import interfaces
from letsencrypt.acme.jose import util


class Field(object):
    """JSON object field.

    :class:`Field` is meant to be used together with
    :class:`JSONObjectWithFields`.

    ``encoder`` (``decoder``) is a callable that accepts a single
    parameter, i.e. a value to be encoded (decoded), and returns the
    serialized (deserialized) value. In case of errors it should raise
    :class:`~letsencrypt.acme.jose.errors.SerializationError`
    (:class:`~letsencrypt.acme.jose.errors.DeserializationError`).

    Note, that ``decoder`` should perform partial serialization only.

    :ivar str json_name: Name of the field when encoded to JSON.
    :ivar default: Default value (used when not present in JSON object).
    :ivar bool omitempty: If ``True`` and the field value is empty, then
        it will not be included in the serialized JSON object, and
        ``default`` will be used for deserialization. Otherwise, if ``False``,
        field is considered as required, value will always be included in the
        serialized JSON objected, and it must also be present when
        deserializing.

    """
    __slots__ = ('json_name', 'default', 'omitempty', 'fdec', 'fenc')

    def __init__(self, json_name, default=None, omitempty=False,
                 decoder=None, encoder=None):
        # pylint: disable=too-many-arguments
        self.json_name = json_name
        self.default = default
        self.omitempty = omitempty

        self.fdec = self.default_decoder if decoder is None else decoder
        self.fenc = self.default_encoder if encoder is None else encoder

    @classmethod
    def _empty(cls, value):
        """Is the provided value cosidered "empty" for this field?

        This is useful for subclasses that might want to override the
        definition of being empty, e.g. for some more exotic data types.

        """
        return not value

    def omit(self, value):
        """Omit the value in output?"""
        return self._empty(value) and self.omitempty

    def _update_params(self, **kwargs):
        current = dict(json_name=self.json_name, default=self.default,
                       omitempty=self.omitempty,
                       decoder=self.fdec, encoder=self.fenc)
        current.update(kwargs)
        return type(self)(**current)  # pylint: disable=star-args

    def decoder(self, fdec):
        """Descriptor to change the decoder on JSON object field."""
        return self._update_params(decoder=fdec)

    def encoder(self, fenc):
        """Descriptor to change the encoder on JSON object field."""
        return self._update_params(encoder=fenc)

    def decode(self, value):
        """Decode a value, optionally with context JSON object."""
        return self.fdec(value)

    def encode(self, value):
        """Encode a value, optionally with context JSON object."""
        return self.fenc(value)

    @classmethod
    def default_decoder(cls, value):
        """Default decoder.

        Recursively deserialize into immutable types (
        :class:`letsencrypt.acme.jose.util.frozendict` instead of
        :func:`dict`, :func:`tuple` instead of :func:`list`).

        """
        # bases cases for different types returned by json.loads
        if isinstance(value, list):
            return tuple(cls.default_decoder(subvalue) for subvalue in value)
        elif isinstance(value, dict):
            return util.frozendict(
                dict((cls.default_decoder(key), cls.default_decoder(value))
                     for key, value in value.iteritems()))
        else:  # integer or string
            return value

    @classmethod
    def default_encoder(cls, value):
        """Default (passthrough) encoder."""
        # field.to_partial_json() is no good as encoder has to do partial
        # serialization only
        return value


class JSONObjectWithFieldsMeta(abc.ABCMeta):
    """Metaclass for :class:`JSONObjectWithFields` and its subclasses.

    It makes sure that, for any class ``cls`` with ``__metaclass__``
    set to ``JSONObjectWithFieldsMeta``:

    1. All fields (attributes of type :class:`Field`) in the class
       definition are moved to the ``cls._fields`` dictionary, where
       keys are field attribute names and values are fields themselves.

    2. ``cls.__slots__`` is extended by all field attribute names
       (i.e. not :attr:`Field.json_name`).

    In a consequence, for a field attribute name ``some_field``,
    ``cls.some_field`` will be a slot descriptor and not an instance
    of :class:`Field`. For example::

      some_field = Field('someField', default=())

      class Foo(object):
          __metaclass__ = JSONObjectWithFieldsMeta
          __slots__ = ('baz',)
          some_field = some_field

      assert Foo.__slots__ == ('some_field', 'baz')
      assert Foo.some_field is not Field

      assert Foo._fields.keys() == ['some_field']
      assert Foo._fields['some_field'] is some_field

    As an implementation note, this metaclass inherits from
    :class:`abc.ABCMeta` (and not the usual :class:`type`) to mitigate
    the metaclass conflict (:class:`ImmutableMap` and
    :class:`JSONDeSerializable`, parents of :class:`JSONObjectWithFields`,
    use :class:`abc.ABCMeta` as its metaclass).

    """

    def __new__(mcs, name, bases, dikt):
        fields = {}
        for key, value in dikt.items():  # not iterkeys() (in-place edit!)
            if isinstance(value, Field):
                fields[key] = dikt.pop(key)

        dikt['__slots__'] = tuple(
            list(dikt.get('__slots__', ())) + fields.keys())
        dikt['_fields'] = fields

        return abc.ABCMeta.__new__(mcs, name, bases, dikt)


class JSONObjectWithFields(util.ImmutableMap, interfaces.JSONDeSerializable):
    # pylint: disable=too-few-public-methods
    """JSON object with fields.

    Example::

      class Foo(JSONObjectWithFields):
          bar = Field('Bar')
          empty = Field('Empty', omitempty=True)

          @bar.encoder
          def bar(value):
              return value + 'bar'

          @bar.decoder
          def bar(value):
              if not value.endswith('bar'):
                  raise errors.DeserializationError('No bar suffix!')
              return value[:-3]

      assert Foo(bar='baz').to_partial_json() == {'Bar': 'bazbar'}
      assert Foo.from_json({'Bar': 'bazbar'}) == Foo(bar='baz')
      assert (Foo.from_json({'Bar': 'bazbar', 'Empty': '!'})
              == Foo(bar='baz', empty='!'))
      assert Foo(bar='baz').bar == 'baz'

    """
    __metaclass__ = JSONObjectWithFieldsMeta

    @classmethod
    def _defaults(cls):
        """Get default fields values."""
        return dict([(slot, field.default) for slot, field
                     in cls._fields.iteritems() if field.omitempty])

    def __init__(self, **kwargs):
        # pylint: disable=star-args
        super(JSONObjectWithFields, self).__init__(
            **(dict(self._defaults(), **kwargs)))

    def fields_to_partial_json(self):
        """Serialize fields to JSON."""
        jobj = {}
        for slot, field in self._fields.iteritems():
            value = getattr(self, slot)

            if field.omit(value):
                logging.debug('Omitting empty field "%s" (%s)', slot, value)
            else:
                try:
                    jobj[field.json_name] = field.encode(value)
                except errors.SerializationError as error:
                    raise errors.SerializationError(
                        'Could not encode {0} ({1}): {2}'.format(
                            slot, value, error))
        return jobj

    def to_partial_json(self):
        return self.fields_to_partial_json()

    @classmethod
    def _check_required(cls, jobj):
        missing = set()
        for _, field in cls._fields.iteritems():
            if not field.omitempty and field.json_name not in jobj:
                missing.add(field.json_name)

        if missing:
            raise errors.DeserializationError(
                'The following field are required: {0}'.format(
                    ','.join(missing)))

    @classmethod
    def fields_from_json(cls, jobj):
        """Deserialize fields from JSON."""
        cls._check_required(jobj)
        fields = {}
        for slot, field in cls._fields.iteritems():
            if field.json_name not in jobj and field.omitempty:
                fields[slot] = field.default
            else:
                value = jobj[field.json_name]
                try:
                    fields[slot] = field.decode(value)
                except errors.DeserializationError as error:
                    raise errors.DeserializationError(
                        'Could not decode {0!r} ({1!r}): {2}'.format(
                            slot, value, error))
        return fields

    @classmethod
    def from_json(cls, jobj):
        return cls(**cls.fields_from_json(jobj))


def decode_b64jose(data, size=None, minimum=False):
    """Decode JOSE Base-64 field.

    :param int size: Required length (after decoding).
    :param bool minimum: If ``True``, then `size` will be treated as
        minimum required length, as opposed to exact equality.

    """
    try:
        decoded = b64.b64decode(data)
    except TypeError as error:
        raise errors.DeserializationError(error)

    if size is not None and ((not minimum and len(decoded) != size)
                             or (minimum and len(decoded) < size)):
        raise errors.DeserializationError()

    return decoded


def decode_hex16(value, size=None, minimum=False):
    """Decode hexlified field.

    :param int size: Required length (after decoding).
    :param bool minimum: If ``True``, then `size` will be treated as
        minimum required length, as opposed to exact equality.

    """
    if size is not None and ((not minimum and len(value) != size * 2)
                             or (minimum and len(value) < size * 2)):
        raise errors.DeserializationError()
    try:
        return binascii.unhexlify(value)
    except TypeError as error:
        raise errors.DeserializationError(error)

def encode_cert(cert):
    """Encode certificate as JOSE Base-64 DER.

    :param cert: Certificate.
    :type cert: :class:`letsencrypt.acme.jose.util.ComparableX509`

    """
    return b64.b64encode(cert.as_der())

def decode_cert(b64der):
    """Decode JOSE Base-64 DER-encoded certificate."""
    try:
        return util.ComparableX509(M2Crypto.X509.load_cert_der_string(
            decode_b64jose(b64der)))
    except M2Crypto.X509.X509Error as error:
        raise errors.DeserializationError(error)

def encode_csr(csr):
    """Encode CSR as JOSE Base-64 DER."""
    return encode_cert(csr)

def decode_csr(b64der):
    """Decode JOSE Base-64 DER-encoded CSR."""
    try:
        return util.ComparableX509(M2Crypto.X509.load_request_der_string(
            decode_b64jose(b64der)))
    except M2Crypto.X509.X509Error as error:
        raise errors.DeserializationError(error)


class TypedJSONObjectWithFields(JSONObjectWithFields):
    """JSON object with type."""

    typ = NotImplemented
    """Type of the object. Subclasses must override."""

    type_field_name = "type"
    """Field name used to distinguish different object types.

    Subclasses will probably have to override this.

    """

    TYPES = NotImplemented
    """Types registered for JSON deserialization"""

    @classmethod
    def register(cls, type_cls, typ=None):
        """Register class for JSON deserialization."""
        typ = type_cls.typ if typ is None else typ
        cls.TYPES[typ] = type_cls
        return type_cls

    @classmethod
    def get_type_cls(cls, jobj):
        """Get the registered class for ``jobj``."""
        if cls in cls.TYPES.itervalues():
            assert jobj[cls.type_field_name]
            # cls is already registered type_cls, force to use it
            # so that, e.g Revocation.from_json(jobj) fails if
            # jobj["type"] != "revocation".
            return cls

        if not isinstance(jobj, dict):
            raise errors.DeserializationError(
                "{0} is not a dictionary object".format(jobj))
        try:
            typ = jobj[cls.type_field_name]
        except KeyError:
            raise errors.DeserializationError("missing type field")

        try:
            return cls.TYPES[typ]
        except KeyError:
            raise errors.UnrecognizedTypeError(typ, jobj)

    def to_partial_json(self):
        """Get JSON serializable object.

        :returns: Serializable JSON object representing ACME typed object.
            :meth:`validate` will almost certainly not work, due to reasons
            explained in :class:`letsencrypt.acme.interfaces.IJSONSerializable`.
        :rtype: dict

        """
        jobj = self.fields_to_partial_json()
        jobj[self.type_field_name] = self.typ
        return jobj

    @classmethod
    def from_json(cls, jobj):
        """Deserialize ACME object from valid JSON object.

        :raises letsencrypt.acme.errors.UnrecognizedTypeError: if type
            of the ACME object has not been registered.

        """
        # make sure subclasses don't cause infinite recursive from_json calls
        type_cls = cls.get_type_cls(jobj)
        return type_cls(**type_cls.fields_from_json(jobj))
