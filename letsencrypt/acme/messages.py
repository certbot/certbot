"""ACME protocol messages."""
import jsonschema

from letsencrypt.acme import challenges
from letsencrypt.acme import errors
from letsencrypt.acme import jose
from letsencrypt.acme import other
from letsencrypt.acme import util


class Message(jose.TypedJSONObjectWithFields):
    # _fields_to_json | pylint: disable=abstract-method
    # pylint: disable=too-few-public-methods
    """ACME message."""
    TYPES = {}
    type_field_name = "type"

    schema = NotImplemented
    """JSON schema the object is tested against in :meth:`from_json`.

    Subclasses must overrride it with a value that is acceptable by
    :func:`jsonschema.validate`, most probably using
    :func:`letsencrypt.acme.util.load_schema`.

    """

    @classmethod
    def from_json(cls, jobj):
        """Deserialize from (possibly invalid) JSON object.

        Note that the input ``jobj`` has not been sanitized in any way.

        :param jobj: JSON object.

        :raises letsencrypt.acme.errors.SchemaValidationError: if the input
            JSON object could not be validated against JSON schema specified
            in :attr:`schema`.
        :raises letsencrypt.acme.jose.errors.DeserializationError: for any
            other generic error in decoding.

        :returns: instance of the class

        """
        msg_cls = cls.get_type_cls(jobj)

        # TODO: is that schema testing still relevant?
        try:
            jsonschema.validate(jobj, msg_cls.schema)
        except jsonschema.ValidationError as error:
            raise errors.SchemaValidationError(error)

        return super(Message, cls).from_json(jobj)


@Message.register  # pylint: disable=too-few-public-methods
class Challenge(Message):
    """ACME "challenge" message.

    :ivar str nonce: Random data, **not** base64-encoded.
    :ivar list challenges: List of
        :class:`~letsencrypt.acme.challenges.Challenge` objects.

    .. todo::
        1. can challenges contain two challenges of the same type?
        2. can challenges contain duplicates?
        3. check "combinations" indices are in valid range
        4. turn "combinations" elements into sets?
        5. turn "combinations" into set?

    """
    typ = "challenge"
    schema = util.load_schema(typ)

    session_id = jose.Field("sessionID")
    nonce = jose.Field("nonce", encoder=jose.b64encode,
                       decoder=jose.decode_b64jose)
    challenges = jose.Field("challenges")
    combinations = jose.Field("combinations", omitempty=True, default=())

    @challenges.decoder
    def challenges(value):  # pylint: disable=missing-docstring,no-self-argument
        return tuple(challenges.Challenge.from_json(chall) for chall in value)

    @property
    def resolved_combinations(self):
        """Combinations with challenges instead of indices."""
        return tuple(tuple(self.challenges[idx] for idx in combo)
                     for combo in self.combinations)


@Message.register  # pylint: disable=too-few-public-methods
class ChallengeRequest(Message):
    """ACME "challengeRequest" message."""
    typ = "challengeRequest"
    schema = util.load_schema(typ)
    identifier = jose.Field("identifier")


@Message.register  # pylint: disable=too-few-public-methods
class Authorization(Message):
    """ACME "authorization" message.

    :ivar jwk: :class:`letsencrypt.acme.jose.JWK`

    """
    typ = "authorization"
    schema = util.load_schema(typ)

    recovery_token = jose.Field("recoveryToken", omitempty=True)
    identifier = jose.Field("identifier", omitempty=True)
    jwk = jose.Field("jwk", decoder=jose.JWK.from_json, omitempty=True)


@Message.register
class AuthorizationRequest(Message):
    """ACME "authorizationRequest" message.

    :ivar str nonce: Random data from the corresponding
        :attr:`Challenge.nonce`, **not** base64-encoded.
    :ivar list responses: List of completed challenges (
        :class:`letsencrypt.acme.challenges.ChallengeResponse`).
    :ivar signature: Signature (:class:`letsencrypt.acme.other.Signature`).

    """
    typ = "authorizationRequest"
    schema = util.load_schema(typ)

    session_id = jose.Field("sessionID")
    nonce = jose.Field("nonce", encoder=jose.b64encode,
                       decoder=jose.decode_b64jose)
    responses = jose.Field("responses")
    signature = jose.Field("signature", decoder=other.Signature.from_json)
    contact = jose.Field("contact", omitempty=True, default=())

    @responses.decoder
    def responses(value):  # pylint: disable=missing-docstring,no-self-argument
        return tuple(challenges.ChallengeResponse.from_json(chall)
                     for chall in value)

    @classmethod
    def create(cls, name, key, sig_nonce=None, **kwargs):
        """Create signed "authorizationRequest".

        :param str name: Hostname

        :param key: Key used for signing.
        :type key: :class:`Crypto.PublicKey.RSA`

        :param str sig_nonce: Nonce used for signature. Useful for testing.
        :kwargs: Any other arguments accepted by the class constructor.

        :returns: Signed "authorizationRequest" ACME message.
        :rtype: :class:`AuthorizationRequest`

        """
        # pylint: disable=too-many-arguments
        signature = other.Signature.from_msg(
            name + kwargs["nonce"], key, sig_nonce)
        return cls(
            signature=signature, contact=kwargs.pop("contact", ()), **kwargs)

    def verify(self, name):
        """Verify signature.

        .. warning:: Caller must check that the public key encoded in the
            :attr:`signature`'s :class:`letsencrypt.acme.jose.JWK` object
            is the correct key for a given context.

        :param str name: Hostname

        :returns: True iff ``signature`` can be verified, False otherwise.
        :rtype: bool

        """
        # self.signature is not Field | pylint: disable=no-member
        return self.signature.verify(name + self.nonce)


@Message.register  # pylint: disable=too-few-public-methods
class Certificate(Message):
    """ACME "certificate" message.

    :ivar certificate: The certificate (:class:`M2Crypto.X509.X509`
        wrapped in :class:`letsencrypt.acme.util.ComparableX509`).

    :ivar list chain: Chain of certificates (:class:`M2Crypto.X509.X509`
        wrapped in :class:`letsencrypt.acme.util.ComparableX509` ).

    """
    typ = "certificate"
    schema = util.load_schema(typ)

    certificate = jose.Field("certificate", encoder=jose.encode_cert,
                             decoder=jose.decode_cert)
    chain = jose.Field("chain", omitempty=True, default=())
    refresh = jose.Field("refresh", omitempty=True)

    @chain.decoder
    def chain(value):  # pylint: disable=missing-docstring,no-self-argument
        return tuple(jose.decode_cert(cert) for cert in value)

    @chain.encoder
    def chain(value):  # pylint: disable=missing-docstring,no-self-argument
        return tuple(jose.encode_cert(cert) for cert in value)


@Message.register
class CertificateRequest(Message):
    """ACME "certificateRequest" message.

    :ivar csr: Certificate Signing Request (:class:`M2Crypto.X509.Request`
        wrapped in :class:`letsencrypt.acme.util.ComparableX509`.
    :ivar signature: Signature (:class:`letsencrypt.acme.other.Signature`).

    """
    typ = "certificateRequest"
    schema = util.load_schema(typ)

    csr = jose.Field("csr", encoder=jose.encode_csr,
                     decoder=jose.decode_csr)
    signature = jose.Field("signature", decoder=other.Signature.from_json)

    @classmethod
    def create(cls, key, sig_nonce=None, **kwargs):
        """Create signed "certificateRequest".

        :param key: Key used for signing.
        :type key: :class:`Crypto.PublicKey.RSA`

        :param str sig_nonce: Nonce used for signature. Useful for testing.
        :kwargs: Any other arguments accepted by the class constructor.

        :returns: Signed "certificateRequest" ACME message.
        :rtype: :class:`CertificateRequest`

        """
        return cls(signature=other.Signature.from_msg(
            kwargs["csr"].as_der(), key, sig_nonce), **kwargs)

    def verify(self):
        """Verify signature.

        .. warning:: Caller must check that the public key encoded in the
            :attr:`signature`'s :class:`letsencrypt.acme.jose.JWK` object
            is the correct key for a given context.

        :returns: True iff ``signature`` can be verified, False otherwise.
        :rtype: bool

        """
        # self.signature is not Field | pylint: disable=no-member
        return self.signature.verify(self.csr.as_der())


@Message.register  # pylint: disable=too-few-public-methods
class Defer(Message):
    """ACME "defer" message."""
    typ = "defer"
    schema = util.load_schema(typ)

    token = jose.Field("token")
    interval = jose.Field("interval", omitempty=True)
    message = jose.Field("message", omitempty=True)


@Message.register  # pylint: disable=too-few-public-methods
class Error(Message):
    """ACME "error" message."""
    typ = "error"
    schema = util.load_schema(typ)

    error = jose.Field("error")
    message = jose.Field("message", omitempty=True)
    more_info = jose.Field("moreInfo", omitempty=True)

    MESSAGE_CODES = {
        "malformed": "The request message was malformed",
        "unauthorized": "The client lacks sufficient authorization",
        "serverInternal": "The server experienced an internal error",
        "notSupported": "The request type is not supported",
        "unknown": "The server does not recognize an ID/token in the request",
        "badCSR": "The CSR is unacceptable (e.g., due to a short key)",
    }


@Message.register  # pylint: disable=too-few-public-methods
class Revocation(Message):
    """ACME "revocation" message."""
    typ = "revocation"
    schema = util.load_schema(typ)


@Message.register
class RevocationRequest(Message):
    """ACME "revocationRequest" message.

    :ivar certificate: Certificate (:class:`M2Crypto.X509.X509`
        wrapped in :class:`letsencrypt.acme.util.ComparableX509`).
    :ivar signature: Signature (:class:`letsencrypt.acme.other.Signature`).

    """
    typ = "revocationRequest"
    schema = util.load_schema(typ)

    certificate = jose.Field("certificate", decoder=jose.decode_cert,
                             encoder=jose.encode_cert)
    signature = jose.Field("signature", decoder=other.Signature.from_json)

    @classmethod
    def create(cls, key, sig_nonce=None, **kwargs):
        """Create signed "revocationRequest".

        :param key: Key used for signing.
        :type key: :class:`Crypto.PublicKey.RSA`

        :param str sig_nonce: Nonce used for signature. Useful for testing.
        :kwargs: Any other arguments accepted by the class constructor.

        :returns: Signed "revocationRequest" ACME message.
        :rtype: :class:`RevocationRequest`

        """
        return cls(signature=other.Signature.from_msg(
            kwargs["certificate"].as_der(), key, sig_nonce), **kwargs)

    def verify(self):
        """Verify signature.

        .. warning:: Caller must check that the public key encoded in the
            :attr:`signature`'s :class:`letsencrypt.acme.jose.JWK` object
            is the correct key for a given context.

        :returns: True iff ``signature`` can be verified, False otherwise.
        :rtype: bool

        """
        # self.signature is not Field | pylint: disable=no-member
        return self.signature.verify(self.certificate.as_der())


@Message.register  # pylint: disable=too-few-public-methods
class StatusRequest(Message):
    """ACME "statusRequest" message."""
    typ = "statusRequest"
    schema = util.load_schema(typ)
    token = jose.Field("token")
