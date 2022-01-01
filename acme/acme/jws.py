"""ACME-specific JWS.

The JWS implementation in josepy only implements the base JOSE standard. In
order to support the new header fields defined in ACME, this module defines some
ACME-specific classes that layer on top of josepy.
"""
from typing import Optional

import josepy as jose


class Header(jose.Header):
    """ACME-specific JOSE Header. Implements nonce, kid, and url.
    """
    nonce: Optional[bytes] = jose.field('nonce', omitempty=True, encoder=jose.encode_b64jose)
    # TODO: Remove the type ignore once https://github.com/certbot/josepy/pull/122 is merged.
    kid: Optional[str] = jose.field('kid', omitempty=True)  # type: ignore[assignment]
    url: Optional[str] = jose.field('url', omitempty=True)

    # Mypy does not understand the josepy magic happening here, and falsely claims
    # that nonce is redefined. Let's ignore the type check here.
    @nonce.decoder  # type: ignore[no-redef,attr-defined,union-attr]
    def nonce(value: str) -> bytes:  # type: ignore[misc]  # pylint: disable=no-self-argument,missing-function-docstring
        try:
            return jose.decode_b64jose(value)
        except jose.DeserializationError as error:
            # TODO: custom error
            raise jose.DeserializationError("Invalid nonce: {0}".format(error))


class Signature(jose.Signature):
    """ACME-specific Signature. Uses ACME-specific Header for customer fields."""
    __slots__ = jose.Signature._orig_slots  # type: ignore[attr-defined]  # pylint: disable=protected-access,no-member

    # TODO: decoder/encoder should accept cls? Otherwise, subclassing
    # JSONObjectWithFields is tricky...
    header_cls = Header
    header: Header = jose.field(
        'header', omitempty=True, default=header_cls(),
        decoder=header_cls.from_json)

    # TODO: decoder should check that nonce is in the protected header


class JWS(jose.JWS):
    """ACME-specific JWS. Includes none, url, and kid in protected header."""
    signature_cls = Signature
    __slots__ = jose.JWS._orig_slots  # type: ignore[attr-defined]  # pylint: disable=protected-access

    @classmethod
    # type: ignore[override]  # pylint: disable=arguments-differ
    def sign(cls, payload: bytes, key: jose.JWK, alg: jose.JWASignature, nonce: Optional[bytes],
             url: Optional[str] = None, kid: Optional[str] = None) -> jose.JWS:
        # Per ACME spec, jwk and kid are mutually exclusive, so only include a
        # jwk field if kid is not provided.
        include_jwk = kid is None
        return super().sign(payload, key=key, alg=alg,
                            protect=frozenset(['nonce', 'url', 'kid', 'jwk', 'alg']),
                            nonce=nonce, url=url, kid=kid,
                            include_jwk=include_jwk)
