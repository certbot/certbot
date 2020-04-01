"""ACME-specific JWS.

The JWS implementation in josepy only implements the base JOSE standard. In
order to support the new header fields defined in ACME, this module defines some
ACME-specific classes that layer on top of josepy.
"""
import josepy as jose


class Header(jose.Header):
    """ACME-specific JOSE Header. Implements nonce, kid, and url.
    """
    nonce = jose.Field('nonce', omitempty=True, encoder=jose.encode_b64jose)
    kid = jose.Field('kid', omitempty=True)
    url = jose.Field('url', omitempty=True)

    @nonce.decoder
    def nonce(value):  # pylint: disable=no-self-argument,missing-function-docstring
        try:
            return jose.decode_b64jose(value)
        except jose.DeserializationError as error:
            # TODO: custom error
            raise jose.DeserializationError("Invalid nonce: {0}".format(error))


class Signature(jose.Signature):
    """ACME-specific Signature. Uses ACME-specific Header for customer fields."""
    __slots__ = jose.Signature._orig_slots  # pylint: disable=no-member

    # TODO: decoder/encoder should accept cls? Otherwise, subclassing
    # JSONObjectWithFields is tricky...
    header_cls = Header
    header = jose.Field(
        'header', omitempty=True, default=header_cls(),
        decoder=header_cls.from_json)

    # TODO: decoder should check that nonce is in the protected header


class JWS(jose.JWS):
    """ACME-specific JWS. Includes none, url, and kid in protected header."""
    signature_cls = Signature
    __slots__ = jose.JWS._orig_slots

    @classmethod
    # pylint: disable=arguments-differ
    def sign(cls, payload, key, alg, nonce, url=None, kid=None):
        # Per ACME spec, jwk and kid are mutually exclusive, so only include a
        # jwk field if kid is not provided.
        include_jwk = kid is None
        return super(JWS, cls).sign(payload, key=key, alg=alg,
                                    protect=frozenset(['nonce', 'url', 'kid', 'jwk', 'alg']),
                                    nonce=nonce, url=url, kid=kid,
                                    include_jwk=include_jwk)
