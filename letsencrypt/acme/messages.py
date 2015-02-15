"""ACME protocol messages."""
import M2Crypto
import zope.interface

from letsencrypt.acme import errors
from letsencrypt.acme import interfaces
from letsencrypt.acme import jose
from letsencrypt.acme import other
from letsencrypt.acme import util


class Message(util.JSONDeSerializable, util.ImmutableMap):
    """ACME message.

    Messages are considered immutable.

    """
    zope.interface.implements(interfaces.IJSONSerializable)

    acme_type = NotImplemented
    """ACME message "type" field. Subclasses must override."""

    TYPES = {}
    """Message types registered for JSON deserialization"""

    @classmethod
    def register(cls, msg_cls):
        """Register class for JSON deserialization."""
        cls.TYPES[msg_cls.acme_type] = msg_cls
        return msg_cls

    def to_json(self):
        """Get JSON serializable object.

        :returns: Serializable JSON object representing ACME message.
            :meth:`validate` will almost certainly not work, due to reasons
            explained in :class:`letsencrypt.acme.interfaces.IJSONSerializable`.
        :rtype: dict

        """
        jobj = self._fields_to_json()
        jobj["type"] = self.acme_type
        return jobj

    def _fields_to_json(self):
        """Prepare ACME message fields for JSON serialiazation.

        Subclasses must override this method.

        :returns: Serializable JSON object containg all ACME message fields
            apart from "type".
        :rtype: dict

        """
        raise NotImplementedError()

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
            msg_cls = cls.TYPES[msg_type]
        except KeyError:
            raise errors.UnrecognizedMessageTypeError(msg_type)

        return msg_cls

    @classmethod
    def from_json(cls, jobj, validate=True):
        """Deserialize validated ACME message from JSON string.

        :param str jobj: JSON object.
        :param bool validate: Validate against schema before deserializing.
            Useful if :class:`JWK` is part of already validated json object.

        :raises letsencrypt.acme.errors.ValidationError: if validation
            was unsuccessful

        :returns: Valid ACME message.
        :rtype: subclass of :class:`Message`

        """
        msg_cls = cls.get_msg_cls(jobj)
        if validate:
            msg_cls.validate_json(jobj)
        # pylint: disable=protected-access
        return msg_cls._from_valid_json(jobj)


@Message.register  # pylint: disable=too-few-public-methods
class Challenge(Message):
    """ACME "challenge" message."""
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

    @classmethod
    def _from_valid_json(cls, jobj):
        return cls(session_id=jobj["sessionID"],
                   nonce=jose.b64decode(jobj["nonce"]),
                   challenges=jobj["challenges"],
                   combinations=jobj.get("combinations", []))


@Message.register  # pylint: disable=too-few-public-methods
class ChallengeRequest(Message):
    """ACME "challengeRequest" message.

    :ivar str identifier: Domain name.

    """
    acme_type = "challengeRequest"
    schema = util.load_schema(acme_type)
    __slots__ = ("identifier",)

    def _fields_to_json(self):
        return {
            "identifier": self.identifier,
        }

    @classmethod
    def _from_valid_json(cls, jobj):
        return cls(identifier=jobj["identifier"])


@Message.register  # pylint: disable=too-few-public-methods
class Authorization(Message):
    """ACME "authorization" message."""
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
    def _from_valid_json(cls, jobj):
        jwk = jobj.get("jwk")
        if jwk is not None:
            jwk = jose.JWK.from_json(jwk, validate=False)
        return cls(recovery_token=jobj.get("recoveryToken"),
                   identifier=jobj.get("identifier"), jwk=jwk)


@Message.register
class AuthorizationRequest(Message):
    """ACME "authorizationRequest" message.

    :ivar str session_id: "sessionID" from the server challenge
    :ivar str nonce: Nonce from the server challenge
    :ivar list responses: List of completed challenges
    :ivar signature: Signature (:class:`letsencrypt.acme.other.Signature`).
    :ivar contact: TODO

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
    def _from_valid_json(cls, jobj):
        return cls(session_id=jobj["sessionID"],
                   nonce=jose.b64decode(jobj["nonce"]),
                   responses=jobj["responses"],
                   signature=other.Signature.from_json(
                       jobj["signature"], validate=False),
                   contact=jobj.get("contact", []))


@Message.register  # pylint: disable=too-few-public-methods
class Certificate(Message):
    """ACME "certificate" message.

    :ivar certificate: The certificate (:class:`M2Crypto.X509.X509`
        wrapped in :class:`letsencrypt.acme.util.ComparableX509`).

    :ivar list chain: Chain of certificates (:class:`M2Crypto.X509.X509` wrapped
        in :class:`letsencrypt.acme.util.ComparableX509` ).

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
    def _decode_cert(cls, b64der):
        return util.ComparableX509(M2Crypto.X509.load_cert_der_string(
            jose.b64decode(b64der)))

    @classmethod
    def _encode_cert(cls, cert):
        return jose.b64encode(cert.as_der())

    @classmethod
    def _from_valid_json(cls, jobj):
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

    @classmethod
    def _decode_csr(cls, b64der):
        return util.ComparableX509(M2Crypto.X509.load_request_der_string(
            jose.b64decode(b64der)))

    @classmethod
    def _encode_csr(cls, csr):
        return jose.b64encode(csr.as_der())

    def _fields_to_json(self):
        return {
            "csr": self._encode_csr(self.csr),
            "signature": self.signature,
        }

    @classmethod
    def _from_valid_json(cls, jobj):
        return cls(csr=cls._decode_csr(jobj["csr"]),
                   signature=other.Signature.from_json(
                       jobj["signature"], validate=False))


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
    def _from_valid_json(cls, jobj):
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
    def _from_valid_json(cls, jobj):
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
    def _from_valid_json(cls, jobj):
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

    @classmethod
    def _decode_cert(cls, b64der):
        return util.ComparableX509(M2Crypto.X509.load_cert_der_string(
            jose.b64decode(b64der)))

    @classmethod
    def _encode_cert(cls, cert):
        return jose.b64encode(cert.as_der())

    def _fields_to_json(self):
        return {
            "certificate": self._encode_cert(self.certificate),
            "signature": self.signature,
        }

    @classmethod
    def _from_valid_json(cls, jobj):
        return cls(certificate=cls._decode_cert(jobj["certificate"]),
                   signature=other.Signature.from_json(
                       jobj["signature"], validate=False))


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
    def _from_valid_json(cls, jobj):
        return cls(token=jobj["token"])
