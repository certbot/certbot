"""ACME protocol messages."""
import json

import jsonschema

from letsencrypt.acme import challenges
from letsencrypt.acme import errors
from letsencrypt.acme import jose
from letsencrypt.acme import other
from letsencrypt.acme import util


class Message(util.TypedACMEObject):
    # _fields_to_json | pylint: disable=abstract-method
    """ACME message."""
    TYPES = {}

    schema = NotImplemented
    """JSON schema the object is tested against in :meth:`from_json`.

    Subclasses must overrride it with a value that is acceptable by
    :func:`jsonschema.validate`, most probably using
    :func:`letsencrypt.acme.util.load_schema`.

    """

    @classmethod
    def get_msg_cls(cls, jobj):
        """Get the registered class for ``jobj``."""
        if cls in cls.TYPES.itervalues():
            # cls is already registered Message type, force to use it
            # so that, e.g Revocation.from_json(jobj) fails if
            # jobj["type"] != "revocation".
            return cls

        if not isinstance(jobj, dict):
            raise errors.ValidationError(
                "{0} is not a dictionary object".format(jobj))
        try:
            msg_type = jobj["type"]
        except KeyError:
            raise errors.ValidationError("missing type field")

        try:
            return cls.TYPES[msg_type]
        except KeyError:
            raise errors.UnrecognizedTypeError(msg_type)

    @classmethod
    def from_json(cls, jobj):
        """Deserialize from (possibly invalid) JSON object.

        Note that the input ``jobj`` has not been sanitized in any way.

        :param jobj: JSON object.

        :raises letsencrypt.acme.errors.SchemaValidationError: if the input
            JSON object could not be validated against JSON schema specified
            in :attr:`schema`.
        :raises letsencrypt.acme.errors.ValidationError: for any other generic
            error in decoding.

        :returns: instance of the class

        """
        msg_cls = cls.get_msg_cls(jobj)

        try:
            jsonschema.validate(jobj, msg_cls.schema)
        except jsonschema.ValidationError as error:
            raise errors.SchemaValidationError(error)

        return cls.from_valid_json(jobj)

    @classmethod
    def json_loads(cls, json_string):
        """Load JSON string."""
        return cls.from_json(json.loads(json_string))

    def json_dumps(self, *args, **kwargs):
        """Dump to JSON string using proper serializer.

        :returns: JSON serialized string.
        :rtype: str

        """
        return json.dumps(
            self, *args, default=util.dump_ijsonserializable, **kwargs)


@Message.register  # pylint: disable=too-few-public-methods
class Challenge(Message):
    """ACME "challenge" message.

    :ivar str nonce: Random data, **not** base64-encoded.
    :ivar list challenges: List of
        :class:`~letsencrypt.acme.challenges.Challenge` objects.

    """
    acme_type = "challenge"
    schema = util.load_schema(acme_type)
    __slots__ = ("session_id", "nonce", "challenges", "combinations")

    def _fields_to_json(self):
        fields = {
            "sessionID": self.session_id,
            "nonce": jose.b64encode(self.nonce),
            "challenges": self.challenges,
        }
        if self.combinations:
            fields["combinations"] = self.combinations
        return fields

    @property
    def resolved_combinations(self):
        """Combinations with challenges instead of indices."""
        return [[self.challenges[idx] for idx in combo]
                for combo in self.combinations]

    @classmethod
    def from_valid_json(cls, jobj):
        # TODO: can challenges contain two challenges of the same type?
        # TODO: can challenges contain duplicates?
        # TODO: check "combinations" indices are in valid range
        # TODO: turn "combinations" elements into sets?
        # TODO: turn "combinations" into set?
        return cls(session_id=jobj["sessionID"],
                   nonce=cls._decode_b64jose(jobj["nonce"]),
                   challenges=[challenges.Challenge.from_valid_json(chall)
                               for chall in jobj["challenges"]],
                   combinations=jobj.get("combinations", []))


@Message.register  # pylint: disable=too-few-public-methods
class ChallengeRequest(Message):
    """ACME "challengeRequest" message."""
    acme_type = "challengeRequest"
    schema = util.load_schema(acme_type)
    __slots__ = ("identifier",)

    def _fields_to_json(self):
        return {
            "identifier": self.identifier,
        }

    @classmethod
    def from_valid_json(cls, jobj):
        return cls(identifier=jobj["identifier"])


@Message.register  # pylint: disable=too-few-public-methods
class Authorization(Message):
    """ACME "authorization" message.

    :ivar jwk: :class:`letsencrypt.acme.other.JWK`

    """
    acme_type = "authorization"
    schema = util.load_schema(acme_type)
    __slots__ = ("recovery_token", "identifier", "jwk")

    def _fields_to_json(self):
        fields = {}
        if self.recovery_token is not None:
            fields["recoveryToken"] = self.recovery_token
        if self.identifier is not None:
            fields["identifier"] = self.identifier
        if self.jwk is not None:
            fields["jwk"] = self.jwk
        return fields

    @classmethod
    def from_valid_json(cls, jobj):
        jwk = jobj.get("jwk")
        if jwk is not None:
            jwk = other.JWK.from_valid_json(jwk)
        return cls(recovery_token=jobj.get("recoveryToken"),
                   identifier=jobj.get("identifier"), jwk=jwk)


@Message.register
class AuthorizationRequest(Message):
    """ACME "authorizationRequest" message.

    :ivar str nonce: Random data from the corresponding
        :attr:`Challenge.nonce`, **not** base64-encoded.
    :ivar list responses: List of completed challenges (
        :class:`letsencrypt.acme.challenges.ChallengeResponse`).
    :ivar signature: Signature (:class:`letsencrypt.acme.other.Signature`).

    """
    acme_type = "authorizationRequest"
    schema = util.load_schema(acme_type)
    __slots__ = ("session_id", "nonce", "responses", "signature", "contact")

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
            signature=signature, contact=kwargs.pop("contact", []), **kwargs)

    def verify(self, name):
        """Verify signature.

        .. warning:: Caller must check that the public key encoded in the
            :attr:`signature`'s :class:`letsencrypt.acme.jose.JWK` object
            is the correct key for a given context.

        :param str name: Hostname

        :returns: True iff ``signature`` can be verified, False otherwise.
        :rtype: bool

        """
        return self.signature.verify(name + self.nonce)

    def _fields_to_json(self):
        fields = {
            "sessionID": self.session_id,
            "nonce": jose.b64encode(self.nonce),
            "responses": self.responses,
            "signature": self.signature,
        }
        if self.contact:
            fields["contact"] = self.contact
        return fields

    @classmethod
    def from_valid_json(cls, jobj):
        return cls(
            session_id=jobj["sessionID"],
            nonce=cls._decode_b64jose(jobj["nonce"]),
            responses=[challenges.ChallengeResponse.from_valid_json(chall)
                       for chall in jobj["responses"]],
            signature=other.Signature.from_valid_json(jobj["signature"]),
            contact=jobj.get("contact", []))


@Message.register  # pylint: disable=too-few-public-methods
class Certificate(Message):
    """ACME "certificate" message.

    :ivar certificate: The certificate (:class:`M2Crypto.X509.X509`
        wrapped in :class:`letsencrypt.acme.util.ComparableX509`).

    :ivar list chain: Chain of certificates (:class:`M2Crypto.X509.X509`
        wrapped in :class:`letsencrypt.acme.util.ComparableX509` ).

    """
    acme_type = "certificate"
    schema = util.load_schema(acme_type)
    __slots__ = ("certificate", "chain", "refresh")

    def _fields_to_json(self):
        fields = {"certificate": self._encode_cert(self.certificate)}
        if self.chain:
            fields["chain"] = [self._encode_cert(cert) for cert in self.chain]
        if self.refresh is not None:
            fields["refresh"] = self.refresh
        return fields

    @classmethod
    def from_valid_json(cls, jobj):
        return cls(certificate=cls._decode_cert(jobj["certificate"]),
                   chain=[cls._decode_cert(cert) for cert in
                          jobj.get("chain", [])],
                   refresh=jobj.get("refresh"))


@Message.register
class CertificateRequest(Message):
    """ACME "certificateRequest" message.

    :ivar csr: Certificate Signing Request (:class:`M2Crypto.X509.Request`
        wrapped in :class:`letsencrypt.acme.util.ComparableX509`.
    :ivar signature: Signature (:class:`letsencrypt.acme.other.Signature`).

    """
    acme_type = "certificateRequest"
    schema = util.load_schema(acme_type)
    __slots__ = ("csr", "signature")

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
        return self.signature.verify(self.csr.as_der())

    def _fields_to_json(self):
        return {
            "csr": self._encode_csr(self.csr),
            "signature": self.signature,
        }

    @classmethod
    def from_valid_json(cls, jobj):
        return cls(csr=cls._decode_csr(jobj["csr"]),
                   signature=other.Signature.from_valid_json(jobj["signature"]))


@Message.register  # pylint: disable=too-few-public-methods
class Defer(Message):
    """ACME "defer" message."""
    acme_type = "defer"
    schema = util.load_schema(acme_type)
    __slots__ = ("token", "interval", "message")

    def _fields_to_json(self):
        fields = {"token": self.token}
        if self.interval is not None:
            fields["interval"] = self.interval
        if self.message is not None:
            fields["message"] = self.message
        return fields

    @classmethod
    def from_valid_json(cls, jobj):
        return cls(token=jobj["token"], interval=jobj.get("interval"),
                   message=jobj.get("message"))


@Message.register  # pylint: disable=too-few-public-methods
class Error(Message):
    """ACME "error" message."""
    acme_type = "error"
    schema = util.load_schema(acme_type)
    __slots__ = ("error", "message", "more_info")

    CODES = {
        "malformed": "The request message was malformed",
        "unauthorized": "The client lacks sufficient authorization",
        "serverInternal": "The server experienced an internal error",
        "notSupported": "The request type is not supported",
        "unknown": "The server does not recognize an ID/token in the request",
        "badCSR": "The CSR is unacceptable (e.g., due to a short key)",
    }

    def _fields_to_json(self):
        fields = {"error": self.error}
        if self.message is not None:
            fields["message"] = self.message
        if self.more_info is not None:
            fields["moreInfo"] = self.more_info
        return fields

    @classmethod
    def from_valid_json(cls, jobj):
        return cls(error=jobj["error"], message=jobj.get("message"),
                   more_info=jobj.get("moreInfo"))


@Message.register  # pylint: disable=too-few-public-methods
class Revocation(Message):
    """ACME "revocation" message."""
    acme_type = "revocation"
    schema = util.load_schema(acme_type)
    __slots__ = ()

    def _fields_to_json(self):
        return {}

    @classmethod
    def from_valid_json(cls, jobj):
        return cls()


@Message.register
class RevocationRequest(Message):
    """ACME "revocationRequest" message.

    :ivar certificate: Certificate (:class:`M2Crypto.X509.X509`
        wrapped in :class:`letsencrypt.acme.util.ComparableX509`).
    :ivar signature: Signature (:class:`letsencrypt.acme.other.Signature`).

    """
    acme_type = "revocationRequest"
    schema = util.load_schema(acme_type)
    __slots__ = ("certificate", "signature")

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
        return self.signature.verify(self.certificate.as_der())

    def _fields_to_json(self):
        return {
            "certificate": self._encode_cert(self.certificate),
            "signature": self.signature,
        }

    @classmethod
    def from_valid_json(cls, jobj):
        return cls(certificate=cls._decode_cert(jobj["certificate"]),
                   signature=other.Signature.from_valid_json(jobj["signature"]))


@Message.register  # pylint: disable=too-few-public-methods
class StatusRequest(Message):
    """ACME "statusRequest" message.

    :ivar unicode token: Token provided in ACME "defer" message.

    """
    acme_type = "statusRequest"
    schema = util.load_schema(acme_type)
    __slots__ = ("token",)

    def _fields_to_json(self):
        return {"token": self.token}

    @classmethod
    def from_valid_json(cls, jobj):
        return cls(token=jobj["token"])
