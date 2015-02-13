"""ACME utilities."""
import binascii
import json
import pkg_resources

import M2Crypto.X509
import zope.interface

from letsencrypt.acme import errors
from letsencrypt.acme import interfaces
from letsencrypt.acme import jose


class ComparableX509(object):  # pylint: disable=too-few-public-methods
    """Wrapper for M2Crypto.X509.* objects that supports __eq__.

    Wraps around:

      - :class:`M2Crypto.X509.X509`
      - :class:`M2Crypto.X509.Request`

    """
    def __init__(self, wrapped):
        self._wrapped = wrapped

    def __getattr__(self, name):
        return getattr(self._wrapped, name)

    def __eq__(self, other):
        return self.as_der() == other.as_der()


def load_schema(name):
    """Load JSON schema from distribution."""
    return json.load(open(pkg_resources.resource_filename(
        __name__, "schemata/%s.json" % name)))


def dump_ijsonserializable(python_object):
    """Serialize IJSONSerializable to JSON.

    This is meant to be passed to :func:`json.dumps` as ``default``
    argument.

    """
    # providedBy | pylint: disable=no-member
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
            '{0}={1!r}'.format(slot, getattr(self, slot))
            for slot in self.__slots__))


class ACMEObject(ImmutableMap):  # pylint: disable=too-few-public-methods
    """ACME object."""
    zope.interface.implements(interfaces.IJSONSerializable)
    zope.interface.classImplements(interfaces.IJSONDeserializable)

    def to_json(self):  # pragma: no cover
        """Serialize to JSON."""
        raise NotImplementedError()

    @classmethod
    def from_valid_json(cls, jobj):  # pragma: no cover
        """Deserialize from valid JSON object."""
        raise NotImplementedError()

    @classmethod
    def _decode_b64jose(cls, data, size=None, minimum=False):
        try:
            decoded = jose.b64decode(data)
        except TypeError:
            raise errors.ValidationError()

        if size is not None and ((not minimum and len(decoded) != size)
                                 or (minimum and len(decoded) < size)):
            raise errors.ValidationError()

        return decoded

    @classmethod
    def _encode_hex16(cls, data):
        return binascii.hexlify(data)

    @classmethod
    def _decode_hex16(cls, data, size=None, minimum=False):
        if size is not None and ((not minimum and len(data) != size * 2)
                                 or (minimum and len(data) < size * 2)):
            raise errors.ValidationError()
        return binascii.unhexlify(data)

    @classmethod
    def _encode_cert(cls, cert):
        return jose.b64encode(cert.as_der())

    @classmethod
    def _decode_cert(cls, b64der):
        try:
            return ComparableX509(M2Crypto.X509.load_cert_der_string(
                cls._decode_b64jose(b64der)))
        except M2Crypto.X509.X509Error:
            raise errors.ValidationError()

    @classmethod
    def _encode_csr(cls, csr):
        return cls._encode_cert(csr)

    @classmethod
    def _decode_csr(cls, b64der):
        try:
            return ComparableX509(M2Crypto.X509.load_request_der_string(
                cls._decode_b64jose(b64der)))
        except M2Crypto.X509.X509Error:
            raise errors.ValidationError()


class TypedACMEObject(ACMEObject):
    """ACME object with type (immutable)."""

    acme_type = NotImplemented
    """ACME "type" field. Subclasses must override."""

    TYPES = NotImplemented
    """Types registered for JSON deserialization"""

    @classmethod
    def register(cls, msg_cls):
        """Register class for JSON deserialization."""
        cls.TYPES[msg_cls.acme_type] = msg_cls
        return msg_cls

    def to_json(self):
        """Get JSON serializable object.

        :returns: Serializable JSON object representing ACME typed object.
            :meth:`validate` will almost certianly not work, due to reasons
            explained in :class:`letsencrypt.acme.interfaces.IJSONSerializable`.
        :rtype: dict

        """
        jobj = self._fields_to_json()
        jobj["type"] = self.acme_type
        return jobj

    def _fields_to_json(self):  # pragma: no cover
        """Prepare ACME object fields for JSON serialiazation.

        Subclasses must override this method.

        :returns: Serializable JSON object containg all ACME object fields
            apart from "type".
        :rtype: dict

        """
        raise NotImplementedError()

    @classmethod
    def from_valid_json(cls, jobj):
        """Deserialize ACME object from valid JSON object.

        :raises letsencrypt.acme.errors.UnrecognizedTypeError: if type
            of the ACME object has not been registered.

        """
        try:
            msg_cls = cls.TYPES[jobj["type"]]
        except KeyError:
            raise errors.UnrecognizedTypeError(jobj["type"])
        return msg_cls.from_valid_json(jobj)
