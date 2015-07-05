"""JSON Web Key."""
import abc
import binascii

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from acme.jose import b64
from acme.jose import errors
from acme.jose import json_util
from acme.jose import util


class JWK(json_util.TypedJSONObjectWithFields):
    # pylint: disable=too-few-public-methods
    """JSON Web Key."""
    type_field_name = 'kty'
    TYPES = {}

    @util.abstractclassmethod
    def load(cls, string):  # pragma: no cover
        """Load key from normalized string form."""
        raise NotImplementedError()

    @abc.abstractmethod
    def public_key(self):  # pragma: no cover
        """Generate JWK with public key.

        For symmetric cryptosystems, this would return ``self``.

        """
        raise NotImplementedError()


@JWK.register
class JWKES(JWK):  # pragma: no cover
    # pylint: disable=abstract-class-not-used
    """ES JWK.

    .. warning:: This is not yet implemented!

    """
    typ = 'ES'

    def fields_to_partial_json(self):
        raise NotImplementedError()

    @classmethod
    def fields_from_json(cls, jobj):
        raise NotImplementedError()

    @classmethod
    def load(cls, string):
        raise NotImplementedError()

    def public_key(self):
        raise NotImplementedError()


@JWK.register
class JWKOct(JWK):
    """Symmetric JWK."""
    typ = 'oct'
    __slots__ = ('key',)

    def fields_to_partial_json(self):
        # TODO: An "alg" member SHOULD also be present to identify the
        # algorithm intended to be used with the key, unless the
        # application uses another means or convention to determine
        # the algorithm used.
        return {'k': self.key}

    @classmethod
    def fields_from_json(cls, jobj):
        return cls(key=jobj['k'])

    @classmethod
    def load(cls, string):
        return cls(key=string)

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
    __slots__ = ('key',)

    @classmethod
    def _encode_param(cls, data):
        def _leading_zeros(arg):
            if len(arg) % 2:
                return '0' + arg
            return arg

        return b64.b64encode(binascii.unhexlify(
            _leading_zeros(hex(data)[2:].rstrip('L'))))

    @classmethod
    def _decode_param(cls, data):
        try:
            return long(binascii.hexlify(json_util.decode_b64jose(data)), 16)
        except ValueError:  # invalid literal for long() with base 16
            raise errors.DeserializationError()

    @classmethod
    def load(cls, string):
        """Load RSA key from string.

        :param str string: RSA key in string form.

        :returns:
        :rtype: :class:`JWKRSA`

        """
        try:
            key = serialization.load_pem_public_key(
                string, backend=default_backend())
        except ValueError:  # ValueError: Could not unserialize key data.
            key = serialization.load_pem_private_key(
                string, password=None, backend=default_backend())
        return cls(key=util.ComparableRSAKey(key))

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
                        "Some private parameters are missing: {0}".format(
                            all_params))
                p, q, dp, dq, qi = tuple(cls._decode_param(x) for x in all_params)

                # TODO: check for oth
            else:
                p, q = rsa.rsa_recover_prime_factors(n, e, d)  # cryptography>=0.8
                dp = rsa.rsa_crt_dmp1(d, p)
                dq = rsa.rsa_crt_dmq1(d, q)
                qi = rsa.rsa_crt_iqmp(p, q)

            key = rsa.RSAPrivateNumbers(
                p, q, d, dp, dq, qi, public_numbers).private_key(default_backend())

        return cls(key=util.ComparableRSAKey(key))

    def fields_to_partial_json(self):
        # pylint: disable=protected-access
        if isinstance(self.key._wrapped, rsa.RSAPublicKey):
            numbers = self.key.public_numbers()
            params = {
                'n': numbers.n,
                'e': numbers.e,
            }
        else: # rsa.RSAPrivateKey
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
                    for key, value in params.iteritems())
