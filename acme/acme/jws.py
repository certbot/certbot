"""ACME JOSE JWS."""
from acme import errors
from acme import jose


class Header(jose.Header):
    """ACME JOSE Header.

    .. todo:: Implement ``acmePath``.

    """
    nonce = jose.Field('nonce', omitempty=True)

    @classmethod
    def validate_nonce(cls, nonce):
        """Validate nonce.

        :returns: ``None`` if ``nonce`` is valid, decoding errors otherwise.

        """
        try:
            jose.b64decode(nonce)
        except (ValueError, TypeError) as error:
            return error
        else:
            return None

    @nonce.decoder
    def nonce(value):  # pylint: disable=missing-docstring,no-self-argument
        error = Header.validate_nonce(value)
        if error is not None:
            # TODO: custom error
            raise errors.Error("Invalid nonce: {0}".format(error))
        return value


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
