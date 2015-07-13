"""ACME JOSE JWS."""
from acme import jose


class Header(jose.Header):
    """ACME JOSE Header.

    .. todo:: Implement ``acmePath``.

    """
    nonce = jose.Field('nonce', omitempty=True, encoder=jose.encode_b64jose)

    @nonce.decoder
    def nonce(value):  # pylint: disable=missing-docstring,no-self-argument
        try:
            return jose.decode_b64jose(value)
        except jose.DeserializationError as error:
            # TODO: custom error
            raise jose.DeserializationError("Invalid nonce: {0}".format(error))


class Signature(jose.Signature):
    """ACME Signature."""
    __slots__ = jose.Signature._orig_slots  # pylint: disable=no-member

    # TODO: decoder/encoder should accept cls? Otherwise, subclassing
    # JSONObjectWithFields is tricky...
    header_cls = Header
    header = jose.Field(
        'header', omitempty=True, default=header_cls(),
        decoder=header_cls.from_json)

    # TODO: decoder should check that nonce is in the protected header


class JWS(jose.JWS):
    """ACME JWS."""
    signature_cls = Signature
    __slots__ = jose.JWS._orig_slots  # pylint: disable=no-member

    @classmethod
    def sign(cls, payload, key, alg, nonce):  # pylint: disable=arguments-differ
        return super(JWS, cls).sign(payload, key=key, alg=alg,
                                    protect=frozenset(['nonce']), nonce=nonce)
