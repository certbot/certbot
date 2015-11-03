"""JSON Web Key."""
import abc
import binascii
import json
import logging

import cryptography.exceptions
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa

import six

from acme.jose import errors
from acme.jose import json_util
from acme.jose import util


logger = logging.getLogger(__name__)


class JWK(json_util.TypedJSONObjectWithFields):
    # pylint: disable=too-few-public-methods
    """JSON Web Key."""
    type_field_name = 'kty'
    TYPES = {}
    cryptography_key_types = ()
    """Subclasses should override."""

    required = NotImplemented
    """Required members of public key's representation as defined by JWK/JWA."""

    _thumbprint_json_dumps_params = {
        # "no whitespace or line breaks before or after any syntactic
        # elements"
        'indent': None,
        'separators': (',', ':'),
        # "members ordered lexicographically by the Unicode [UNICODE]
        # code points of the member names"
        'sort_keys': True,
    }

    def thumbprint(self, hash_function=hashes.SHA256):
        """Compute JWK Thumbprint.

        https://tools.ietf.org/html/rfc7638

        :returns bytes:

        """
        digest = hashes.Hash(hash_function(), backend=default_backend())
        digest.update(json.dumps(
            dict((k, v) for k, v in six.iteritems(self.to_json())
                 if k in self.required),
            **self._thumbprint_json_dumps_params).encode())
        return digest.finalize()

    @abc.abstractmethod
    def public_key(self):  # pragma: no cover
        """Generate JWK with public key.

        For symmetric cryptosystems, this would return ``self``.

        """
        raise NotImplementedError()

    @classmethod
    def _load_cryptography_key(cls, data, password=None, backend=None):
        backend = default_backend() if backend is None else backend
        exceptions = {}

        # private key?
        for loader in (serialization.load_pem_private_key,
                       serialization.load_der_private_key):
            try:
                return loader(data, password, backend)
            except (ValueError, TypeError,
                    cryptography.exceptions.UnsupportedAlgorithm) as error:
                exceptions[loader] = error

        # public key?
        for loader in (serialization.load_pem_public_key,
                       serialization.load_der_public_key):
            try:
                return loader(data, backend)
            except (ValueError,
                    cryptography.exceptions.UnsupportedAlgorithm) as error:
                exceptions[loader] = error

        # no luck
        raise errors.Error('Unable to deserialize key: {0}'.format(exceptions))

    @classmethod
    def load(cls, data, password=None, backend=None):
        """Load serialized key as JWK.

        :param str data: Public or private key serialized as PEM or DER.
        :param str password: Optional password.
        :param backend: A `.PEMSerializationBackend` and
            `.DERSerializationBackend` provider.

        :raises errors.Error: if unable to deserialize, or unsupported
            JWK algorithm

        :returns: JWK of an appropriate type.
        :rtype: `JWK`

        """
        try:
            key = cls._load_cryptography_key(data, password, backend)
        except errors.Error as error:
            logger.debug('Loading symmetric key, assymentric failed: %s', error)
            return JWKOct(key=data)

        if cls.typ is not NotImplemented and not isinstance(
                key, cls.cryptography_key_types):
            raise errors.Error('Unable to deserialize {0} into {1}'.format(
                key.__class__, cls.__class__))
        for jwk_cls in six.itervalues(cls.TYPES):
            if isinstance(key, jwk_cls.cryptography_key_types):
                return jwk_cls(key=key)
        raise errors.Error('Unsupported algorithm: {0}'.format(key.__class__))


@JWK.register
class JWKES(JWK):  # pragma: no cover
    # pylint: disable=abstract-class-not-used
    """ES JWK.

    .. warning:: This is not yet implemented!

    """
    typ = 'ES'
    cryptography_key_types = (
        ec.EllipticCurvePublicKey, ec.EllipticCurvePrivateKey)
    required = ('crv', JWK.type_field_name, 'x', 'y')

    def fields_to_partial_json(self):
        raise NotImplementedError()

    @classmethod
    def fields_from_json(cls, jobj):
        raise NotImplementedError()

    def public_key(self):
        raise NotImplementedError()


@JWK.register
class JWKOct(JWK):
    """Symmetric JWK."""
    typ = 'oct'
    __slots__ = ('key',)
    required = ('k', JWK.type_field_name)

    def fields_to_partial_json(self):
        # TODO: An "alg" member SHOULD also be present to identify the
        # algorithm intended to be used with the key, unless the
        # application uses another means or convention to determine
        # the algorithm used.
        return {'k': json_util.encode_b64jose(self.key)}

    @classmethod
    def fields_from_json(cls, jobj):
        return cls(key=json_util.decode_b64jose(jobj['k']))

    def public_key(self):
        return self


@JWK.register
class JWKRSA(JWK):
    """RSA JWK.

    :ivar key: `cryptography.hazmat.primitives.rsa.RSAPrivateKey`
        or `cryptography.hazmat.primitives.rsa.RSAPublicKey` wrapped
        in `.ComparableRSAKey`

    """
    typ = 'RSA'
    cryptography_key_types = (rsa.RSAPublicKey, rsa.RSAPrivateKey)
    __slots__ = ('key',)
    required = ('e', JWK.type_field_name, 'n')

    def __init__(self, *args, **kwargs):
        if 'key' in kwargs and not isinstance(
                kwargs['key'], util.ComparableRSAKey):
            kwargs['key'] = util.ComparableRSAKey(kwargs['key'])
        super(JWKRSA, self).__init__(*args, **kwargs)

    @classmethod
    def _encode_param(cls, data):
        """Encode Base64urlUInt.

        :type data: long
        :rtype: unicode

        """
        def _leading_zeros(arg):
            if len(arg) % 2:
                return '0' + arg
            return arg

        return json_util.encode_b64jose(binascii.unhexlify(
            _leading_zeros(hex(data)[2:].rstrip('L'))))

    @classmethod
    def _decode_param(cls, data):
        """Decode Base64urlUInt."""
        try:
            return int(binascii.hexlify(json_util.decode_b64jose(data)), 16)
        except ValueError:  # invalid literal for long() with base 16
            raise errors.DeserializationError()

    def public_key(self):
        return type(self)(key=self.key.public_key())

    @classmethod
    def fields_from_json(cls, jobj):
        # pylint: disable=invalid-name
        n, e = (cls._decode_param(jobj[x]) for x in ('n', 'e'))
        public_numbers = rsa.RSAPublicNumbers(e=e, n=n)
        if 'd' not in jobj:  # public key
            key = public_numbers.public_key(default_backend())
        else:  # private key
            d = cls._decode_param(jobj['d'])
            if ('p' in jobj or 'q' in jobj or 'dp' in jobj or
                    'dq' in jobj or 'qi' in jobj or 'oth' in jobj):
                # "If the producer includes any of the other private
                # key parameters, then all of the others MUST be
                # present, with the exception of "oth", which MUST
                # only be present when more than two prime factors
                # were used."
                p, q, dp, dq, qi, = all_params = tuple(
                    jobj.get(x) for x in ('p', 'q', 'dp', 'dq', 'qi'))
                if tuple(param for param in all_params if param is None):
                    raise errors.Error(
                        'Some private parameters are missing: {0}'.format(
                            all_params))
                p, q, dp, dq, qi = tuple(
                    cls._decode_param(x) for x in all_params)

                # TODO: check for oth
            else:
                # cryptography>=0.8
                p, q = rsa.rsa_recover_prime_factors(n, e, d)
                dp = rsa.rsa_crt_dmp1(d, p)
                dq = rsa.rsa_crt_dmq1(d, q)
                qi = rsa.rsa_crt_iqmp(p, q)

            key = rsa.RSAPrivateNumbers(
                p, q, d, dp, dq, qi, public_numbers).private_key(
                    default_backend())

        return cls(key=key)

    def fields_to_partial_json(self):
        # pylint: disable=protected-access
        if isinstance(self.key._wrapped, rsa.RSAPublicKey):
            numbers = self.key.public_numbers()
            params = {
                'n': numbers.n,
                'e': numbers.e,
            }
        else:  # rsa.RSAPrivateKey
            private = self.key.private_numbers()
            public = self.key.public_key().public_numbers()
            params = {
                'n': public.n,
                'e': public.e,
                'd': private.d,
                'p': private.p,
                'q': private.q,
                'dp': private.dmp1,
                'dq': private.dmq1,
                'qi': private.iqmp,
            }
        return dict((key, self._encode_param(value))
                    for key, value in six.iteritems(params))
