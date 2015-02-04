"""ACME protocol messages."""
import json
import pkg_resources

import jsonschema
import M2Crypto
import zope.interface

from letsencrypt.acme import errors
from letsencrypt.acme import interfaces
from letsencrypt.acme import jose
from letsencrypt.acme import other
from letsencrypt.acme import util


SCHEMATA = dict([
    (schema, json.load(open(pkg_resources.resource_filename(
        __name__, "schemata/%s.json" % schema)))) for schema in [
            "authorization",
            "authorizationRequest",
            "certificate",
            "certificateRequest",
            "challenge",
            "challengeRequest",
            "defer",
            "error",
            "revocation",
            "revocationRequest",
            "statusRequest",
        ]
])


class Message(object):
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

    @classmethod
    def schema(cls, schemata=None):
        """Get JSON schema for this ACME message.

        :param dict schemata: Mapping from type name to JSON Schema
            definition. Useful for testing.

        """
        schemata = SCHEMATA if schemata is None else schemata
        return schemata[cls.acme_type]

    def to_json(self):
        """Get JSON serializable object.

        :returns: Serializable JSON object representing ACME message.
            :meth:`validate` will almost certianly not work, due to reasons
            explained in :class:`letsencrypt.acme.interfaces.IJSONSerializable`.
        :rtype: dict

        """
        json_object = self._fields_to_json()
        json_object["type"] = self.acme_type
        return json_object

    def _fields_to_json(self):
        """Prepare ACME message fields for JSON serialiazation.

        Subclasses must override this method.

        :returns: Serializable JSON object containg all ACME message fields
            apart from "type".
        :rtype: dict

        """
        raise NotImplementedError

    def json_dumps(self):
        """Dump to JSON using proper serializer.

        :returns: JSON serialized string.
        :rtype: str

        """
        return json.dumps(self, default=util.dump_ijsonserializable)

    @classmethod
    def validate(cls, json_object, schemata=None):
        """Is JSON object a valid ACME message?

        :param str json_object: JSON object

        :param dict schemata: Mapping from type name to JSON Schema
            definition. Useful for testing.

        :returns: ACME message class, subclassing :class:`Message`.

        :raises letsencrypt.acme.errors.ValidationError: if validation
            was unsuccessful

        """
        schemata = SCHEMATA if schemata is None else schemata

        if not isinstance(json_object, dict):
            raise errors.ValidationError(
                "{0} is not a dictionary object".format(json_object))
        try:
            msg_type = json_object["type"]
        except KeyError:
            raise errors.ValidationError("missing type field")

        try:
            schema = schemata[msg_type]  # pylint: disable=redefined-outer-name
            msg_cls = cls.TYPES[msg_type]
        except KeyError:
            raise errors.UnrecognnizedMessageTypeError(msg_type)

        try:
            jsonschema.validate(json_object, schema)
        except jsonschema.ValidationError as error:
            raise errors.SchemaValidationError(error)

        return msg_cls

    @classmethod
    def from_json(cls, json_string, schemata=None):
        """Deserialize validated ACME message from JSON string.

        :param str json_string: JSON serialize string.
        :param dict schemata: Mapping from type name to JSON Schema
            definition. Useful for testing.

        :raises letsencrypt.acme.errors.ValidationError: if validation
            was unsuccessful

        :returns: Valid ACME message.
        :rtype: subclass of :class:`Message`

        """
        json_object = json.loads(json_string)
        msg_cls = cls.validate(json_object, schemata)
        # pylint: disable=protected-access
        return msg_cls._valid_from_json(json_object)

    @classmethod
    def _valid_from_json(cls, json_object):
        """Deserialize from valid ACME message JSON object.

        Subclasses must override.

        :param json_object: Schema validated ACME message JSON object.
        :type json_object: dict

        :returns: Valid ACME message.
        :rtype: subclass of :class:`Message`

        """
        raise NotImplementedError


@Message.register  # pylint: disable=too-few-public-methods
class Challenge(Message):
    """ACME "challenge" message."""
    acme_type = "challenge"

    def __init__(self, session_id, nonce, challenges, combinations=None):
        self.session_id = session_id
        self.nonce = nonce
        self.challenges = challenges
        self.combinations = [] if combinations is None else combinations

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
    def _valid_from_json(cls, json_object):
        return cls(json_object["sessionID"],
                   jose.b64decode(json_object["nonce"]),
                   json_object["challenges"], json_object.get("combinations"))


@Message.register  # pylint: disable=too-few-public-methods
class ChallengeRequest(Message):
    """ACME "challengeRequest" message.

    :ivar str identifier: Domain name.

    """
    acme_type = "challengeRequest"

    def __init__(self, identifier):
        self.identifier = identifier

    def _fields_to_json(self):
        return {
            "identifier": self.identifier,
        }

    @classmethod
    def _valid_from_json(cls, json_string):
        return cls(json_string["identifier"])


@Message.register  # pylint: disable=too-few-public-methods
class Authorization(Message):
    """ACME "authorization" message."""
    acme_type = "authorization"

    def __init__(self, recovery_token=None, identifier=None, jwk=None):
        self.recovery_token = recovery_token
        self.identifier = identifier
        self.jwk = jwk

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
    def _valid_from_json(cls, json_object):
        jwk = json_object.get("jwk")
        if jwk is not None:
            jwk = jose.JWK.from_json(jwk)
        return cls(json_object.get("recoveryToken"),
                   json_object.get("identifier"),
                   jwk)


@Message.register
class AuthorizationRequest(Message):
    """ACME "authorizationRequest" message.

    :ivar str session_id: "sessionID" from the server challenge
    :ivar str name: Hostname
    :ivar str nonce: Nonce from the server challenge
    :ivar list responses: List of completed challenges
    :ivar contact: TODO

    """
    acme_type = "authorizationRequest"

    def __init__(self, session_id, nonce, responses, signature, contact=None):
        self.session_id = session_id
        self.nonce = nonce
        self.responses = responses
        self.signature = signature
        self.contact = [] if contact is None else contact

    @classmethod
    def create(cls, session_id, nonce, responses, name, key,
               sig_nonce=None, contact=None):
        """Create signed "authorizationRequest".

        :param key: Key used for signing.
        :type key: :class:`Crypto.PublicKey.RSA`

        :param str sig_nonce: Nonce used for signature. Useful for testing.

        :returns: Signed "authorizationRequest" ACME message.
        :rtype: :class:`AuthorizationRequest`

        """
        # pylint: disable=too-many-arguments
        signature = other.Signature.from_msg(name + nonce, key, sig_nonce)
        return cls(session_id, nonce, responses, signature, contact)

    def verify(self, name):
        """Verify signature.

        :param str name: Hostname

        :returns: True iff ``signature`` can be verified, False otherwise.
        :rtype: bool

        """
        # TODO: must also check that the public key encoded in the JWK object
        # is the correct key for a given context.
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
    def _valid_from_json(cls, json_object):
        return cls(json_object["sessionID"],
                   jose.b64decode(json_object["nonce"]),
                   json_object["responses"],
                   other.Signature.from_json(json_object["signature"]),
                   json_object.get("contact"))


@Message.register  # pylint: disable=too-few-public-methods
class Certificate(Message):
    """ACME "certificate" message.

    :ivar certificate: TODO
    :type certificate: :class:`M2Crypto.X509` TODO

    """
    acme_type = "certificate"

    def __init__(self, certificate, chain=None, refresh=None):
        self.certificate = certificate
        self.chain = [] if chain is None else chain
        self.refresh = refresh

    def _fields_to_json(self):
        fields = {
            "certificate": jose.b64encode(self.certificate.as_der())}
        if self.chain is not None:
            fields["chain"] = self.chain
        if self.refresh is not None:
            fields["refresh"] = self.refresh
        return fields

    @classmethod
    def _valid_from_json(cls, json_object):
        certificate = M2Crypto.X509.load_cert_der_string(
            jose.b64decode(json_object["certificate"]))
        return cls(certificate,
                   json_object.get("chain"),
                   json_object.get("refresh"))


@Message.register
class CertificateRequest(Message):
    """ACME "certificateRequest" message.

    :ivar str csr: DER encoded CSR.
    :ivar signature: Signature.
    :type signature: :class:`letsencrypt.acme.other.Signature`

    """
    acme_type = "certificateRequest"

    def __init__(self, csr, signature):
        self.csr = csr
        self.signature = signature

    @classmethod
    def create(cls, csr, key, nonce=None):
        """Create signed "certificateRequest".

        :param key: Key used for signing.
        :type key: :class:`Crypto.PublicKey.RSA`

        :param str nonce: Nonce used for signature. Useful for testing.

        :returns: Signed "certificateRequest" ACME message.
        :rtype: :class:`CertificateRequest`

        """
        return cls(csr, other.Signature.from_msg(csr, key, nonce))

    def verify(self):
        """Verify signature.

        :returns: True iff ``signature`` can be verified, False otherwise.
        :rtype: bool

        """
        # TODO: must also check that the public key encoded in the JWK object
        # is the correct key for a given context.
        return self.signature.verify(self.csr)

    def _fields_to_json(self):
        return {
            "csr": jose.b64encode(self.csr),
            "signature": self.signature,
        }

    @classmethod
    def _valid_from_json(cls, json_object):
        return cls(jose.b64decode(json_object["csr"]),
                   other.Signature.from_json(json_object["signature"]))


@Message.register  # pylint: disable=too-few-public-methods
class Defer(Message):
    """ACME "defer" message."""
    acme_type = "defer"

    def __init__(self, token, interval=None, message=None):
        self.token = token
        self.interval = interval  # TODO: int
        self.message = message

    def _fields_to_json(self):
        fields = {"token": self.token}
        if self.interval is not None:
            fields["interval"] = self.interval
        if self.message is not None:
            fields["message"] = self.message
        return fields

    @classmethod
    def _valid_from_json(cls, json_object):
        return cls(json_object["token"], json_object.get("interval"),
                   json_object.get("message"))


@Message.register  # pylint: disable=too-few-public-methods
class Error(Message):
    """ACME "error" message."""
    acme_type = "error"

    CODES = {
        "malformed": "The request message was malformed",
        "unauthorized": "The client lacks sufficient authorization",
        "serverInternal": "The server experienced an internal error",
        "notSupported": "The request type is not supported",
        "unknown": "The server does not recognize an ID/token in the request",
        "badCSR": "The CSR is unacceptable (e.g., due to a short key)",
    }

    def __init__(self, error, message=None, more_info=None):
        assert error in self.CODES  # TODO: already checked by schema validation
        self.error = error
        self.message = message
        self.more_info = more_info

    def _fields_to_json(self):
        fields = {"error": self.error}
        if self.message is not None:
            fields["message"] = self.message
        if self.more_info is not None:
            fields["moreInfo"] = self.more_info
        return fields

    @classmethod
    def _valid_from_json(cls, json_object):
        return cls(json_object["error"], json_object.get("message"),
                   json_object.get("more_info"))


@Message.register  # pylint: disable=too-few-public-methods
class Revocation(Message):
    """ACME "revocation" message."""
    acme_type = "revocation"

    def _fields_to_json(self):
        return {}

    @classmethod
    def _valid_from_json(cls, json_object):
        return cls()


@Message.register
class RevocationRequest(Message):
    """ACME "revocationRequest" message.

    :iver str certificate: DER encoded certificate.
    :iver str key: Key in string form. Accepted formats
        are the same as for `Crypto.PublicKey.RSA.importKey`.
    :ivar str nonce: Nonce used for signature. Useful for testing.

    """
    acme_type = "revocationRequest"

    def __init__(self, certificate, signature):
        self.certificate = certificate
        self.signature = signature

    @classmethod
    def create(cls, certificate, key, nonce=None):
        """Create signed "revocationRequest".

        :param key: Key used for signing.
        :type key: :class:`Crypto.PublicKey.RSA`

        :param str nonce: Nonce used for signature. Useful for testing.

        :returns: Signed "revocationRequest" ACME message.
        :rtype: :class:`RevocationRequest`

        """
        return cls(certificate,
                   other.Signature.from_msg(certificate, key, nonce))

    def verify(self):
        """Verify signature.

        :returns: True iff ``signature`` can be verified, False otherwise.
        :rtype: bool

        """
        # TODO: must also check that the public key encoded in the JWK object
        # is the correct key for a given context.
        return self.signature.verify(self.certificate)

    def _fields_to_json(self):
        return {
            "certificate": jose.b64encode(self.certificate),
            "signature": self.signature,
        }

    @classmethod
    def _valid_from_json(cls, json_string):
        return cls(jose.b64decode(json_string["certificate"]),
                   other.Signature.from_json(json_string["signature"]))


@Message.register  # pylint: disable=too-few-public-methods
class StatusRequest(Message):
    """ACME "statusRequest" message.

    :ivar unicode token: Token provided in ACME "defer" message.

    """
    acme_type = "statusRequest"

    def __init__(self, token):
        self.token = token

    def _fields_to_json(self):
        return {
            "token": self.token,
        }

    @classmethod
    def _valid_from_json(cls, json_string):
        return cls(json_string["token"])
