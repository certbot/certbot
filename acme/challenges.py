"""ACME Identifier Validation Challenges."""
import binascii
import functools
import hashlib

import Crypto.Random

from acme import jose
from acme import other


# pylint: disable=too-few-public-methods


class Challenge(jose.TypedJSONObjectWithFields):
    # _fields_to_partial_json | pylint: disable=abstract-method
    """ACME challenge."""
    TYPES = {}


class ContinuityChallenge(Challenge):  # pylint: disable=abstract-method
    """Client validation challenges."""


class DVChallenge(Challenge):  # pylint: disable=abstract-method
    """Domain validation challenges."""


class ChallengeResponse(jose.TypedJSONObjectWithFields):
    # _fields_to_partial_json | pylint: disable=abstract-method
    """ACME challenge response."""
    TYPES = {}

    @classmethod
    def from_json(cls, jobj):
        if jobj is None:
            # if the client chooses not to respond to a given
            # challenge, then the corresponding entry in the response
            # array is set to None (null)
            return None
        return super(ChallengeResponse, cls).from_json(jobj)


@Challenge.register
class SimpleHTTP(DVChallenge):
    """ACME "simpleHttp" challenge."""
    typ = "simpleHttp"
    token = jose.Field("token")


@ChallengeResponse.register
class SimpleHTTPResponse(ChallengeResponse):
    """ACME "simpleHttp" challenge response."""
    typ = "simpleHttp"
    path = jose.Field("path")

    URI_TEMPLATE = "https://{domain}/.well-known/acme-challenge/{path}"
    """URI template for HTTPS server provisioned resource."""

    def uri(self, domain):
        """Create an URI to the provisioned resource.

        Forms an URI to the HTTPS server provisioned resource (containing
        :attr:`~SimpleHTTP.token`) by populating the :attr:`URI_TEMPLATE`.

        :param str domain: Domain name being verified.

        """
        return self.URI_TEMPLATE.format(domain=domain, path=self.path)


@Challenge.register
class DVSNI(DVChallenge):
    """ACME "dvsni" challenge.

    :ivar str r: Random data, **not** base64-encoded.
    :ivar str nonce: Random data, **not** hex-encoded.

    """
    typ = "dvsni"

    DOMAIN_SUFFIX = ".acme.invalid"
    """Domain name suffix."""

    R_SIZE = 32
    """Required size of the :attr:`r` in bytes."""

    NONCE_SIZE = 16
    """Required size of the :attr:`nonce` in bytes."""

    PORT = 443
    """Port to perform DVSNI challenge."""

    r = jose.Field("r", encoder=jose.b64encode,  # pylint: disable=invalid-name
                   decoder=functools.partial(jose.decode_b64jose, size=R_SIZE))
    nonce = jose.Field("nonce", encoder=binascii.hexlify,
                       decoder=functools.partial(functools.partial(
                           jose.decode_hex16, size=NONCE_SIZE)))

    @property
    def nonce_domain(self):
        """Domain name used in SNI."""
        return binascii.hexlify(self.nonce) + self.DOMAIN_SUFFIX


@ChallengeResponse.register
class DVSNIResponse(ChallengeResponse):
    """ACME "dvsni" challenge response.

    :param str s: Random data, **not** base64-encoded.

    """
    typ = "dvsni"

    DOMAIN_SUFFIX = DVSNI.DOMAIN_SUFFIX
    """Domain name suffix."""

    S_SIZE = 32
    """Required size of the :attr:`s` in bytes."""

    s = jose.Field("s", encoder=jose.b64encode,  # pylint: disable=invalid-name
                   decoder=functools.partial(jose.decode_b64jose, size=S_SIZE))

    def __init__(self, s=None, *args, **kwargs):
        s = Crypto.Random.get_random_bytes(self.S_SIZE) if s is None else s
        super(DVSNIResponse, self).__init__(s=s, *args, **kwargs)

    def z(self, chall):  # pylint: disable=invalid-name
        """Compute the parameter ``z``.

        :param challenge: Corresponding challenge.
        :type challenge: :class:`DVSNI`

        """
        z = hashlib.new("sha256")  # pylint: disable=invalid-name
        z.update(chall.r)
        z.update(self.s)
        return z.hexdigest()

    def z_domain(self, chall):
        """Domain name for certificate subjectAltName."""
        return self.z(chall) + self.DOMAIN_SUFFIX

@Challenge.register
class RecoveryContact(ContinuityChallenge):
    """ACME "recoveryContact" challenge."""
    typ = "recoveryContact"

    activation_url = jose.Field("activationURL", omitempty=True)
    success_url = jose.Field("successURL", omitempty=True)
    contact = jose.Field("contact", omitempty=True)


@ChallengeResponse.register
class RecoveryContactResponse(ChallengeResponse):
    """ACME "recoveryContact" challenge response."""
    typ = "recoveryContact"
    token = jose.Field("token", omitempty=True)


@Challenge.register
class RecoveryToken(ContinuityChallenge):
    """ACME "recoveryToken" challenge."""
    typ = "recoveryToken"


@ChallengeResponse.register
class RecoveryTokenResponse(ChallengeResponse):
    """ACME "recoveryToken" challenge response."""
    typ = "recoveryToken"
    token = jose.Field("token", omitempty=True)


@Challenge.register
class ProofOfPossession(ContinuityChallenge):
    """ACME "proofOfPossession" challenge.

    :ivar str nonce: Random data, **not** base64-encoded.
    :ivar hints: Various clues for the client (:class:`Hints`).

    """
    typ = "proofOfPossession"

    NONCE_SIZE = 16

    class Hints(jose.JSONObjectWithFields):
        """Hints for "proofOfPossession" challenge.

        :ivar jwk: JSON Web Key (:class:`acme.jose.JWK`)
        :ivar list certs: List of :class:`acme.jose.ComparableX509`
            certificates.

        """
        jwk = jose.Field("jwk", decoder=jose.JWK.from_json)
        cert_fingerprints = jose.Field(
            "certFingerprints", omitempty=True, default=())
        certs = jose.Field("certs", omitempty=True, default=())
        subject_key_identifiers = jose.Field(
            "subjectKeyIdentifiers", omitempty=True, default=())
        serial_numbers = jose.Field("serialNumbers", omitempty=True, default=())
        issuers = jose.Field("issuers", omitempty=True, default=())
        authorized_for = jose.Field("authorizedFor", omitempty=True, default=())

        @certs.encoder
        def certs(value):  # pylint: disable=missing-docstring,no-self-argument
            return tuple(jose.encode_cert(cert) for cert in value)

        @certs.decoder
        def certs(value):  # pylint: disable=missing-docstring,no-self-argument
            return tuple(jose.decode_cert(cert) for cert in value)

    alg = jose.Field("alg", decoder=jose.JWASignature.from_json)
    nonce = jose.Field(
        "nonce", encoder=jose.b64encode, decoder=functools.partial(
            jose.decode_b64jose, size=NONCE_SIZE))
    hints = jose.Field("hints", decoder=Hints.from_json)


@ChallengeResponse.register
class ProofOfPossessionResponse(ChallengeResponse):
    """ACME "proofOfPossession" challenge response.

    :ivar str nonce: Random data, **not** base64-encoded.
    :ivar signature: :class:`~acme.other.Signature` of this message.

    """
    typ = "proofOfPossession"

    NONCE_SIZE = ProofOfPossession.NONCE_SIZE

    nonce = jose.Field(
        "nonce", encoder=jose.b64encode, decoder=functools.partial(
            jose.decode_b64jose, size=NONCE_SIZE))
    signature = jose.Field("signature", decoder=other.Signature.from_json)

    def verify(self):
        """Verify the challenge."""
        # self.signature is not Field | pylint: disable=no-member
        return self.signature.verify(self.nonce)


@Challenge.register
class DNS(DVChallenge):
    """ACME "dns" challenge."""
    typ = "dns"
    token = jose.Field("token")


@ChallengeResponse.register
class DNSResponse(ChallengeResponse):
    """ACME "dns" challenge response."""
    typ = "dns"
