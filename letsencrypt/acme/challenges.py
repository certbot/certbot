"""ACME Identifier Validation Challenges."""
import binascii
import functools
import hashlib

import Crypto.Random

from letsencrypt.acme import jose
from letsencrypt.acme import other
from letsencrypt.acme import util


# pylint: disable=too-few-public-methods


class Challenge(util.TypedACMEObject):
    # _fields_to_json | pylint: disable=abstract-method
    """ACME challenge."""
    TYPES = {}


class ClientChallenge(Challenge):  # pylint: disable=abstract-method
    """Client validation challenges."""


class DVChallenge(Challenge):  # pylint: disable=abstract-method
    """Domain validation challenges."""


class ChallengeResponse(util.TypedACMEObject):
    # _fields_to_json | pylint: disable=abstract-method
    """ACME challenge response."""
    TYPES = {}

    @classmethod
    def from_valid_json(cls, jobj):
        if jobj is None:
            # if the client chooses not to respond to a given
            # challenge, then the corresponding entry in the response
            # array is set to None (null)
            return None
        return super(ChallengeResponse, cls).from_valid_json(jobj)


@Challenge.register
class SimpleHTTPS(DVChallenge):
    """ACME "simpleHttps" challenge."""
    acme_type = "simpleHttps"
    __slots__ = ("token",)

    def _fields_to_json(self):
        return {"token": self.token}

    @classmethod
    def from_valid_json(cls, jobj):
        return cls(token=jobj["token"])


@ChallengeResponse.register
class SimpleHTTPSResponse(ChallengeResponse):
    """ACME "simpleHttps" challenge response."""
    acme_type = "simpleHttps"
    __slots__ = ("path",)

    URI_TEMPLATE = "https://{domain}/.well-known/acme-challenge/{path}"
    """URI template for HTTPS server provisioned resource."""

    def uri(self, domain):
        """Create an URI to the provisioned resource.

        Forms an URI to the HTTPS server provisioned resource (containing
        :attr:`~SimpleHTTPS.token`) by populating the :attr:`URI_TEMPLATE`.

        :param str domain: Domain name being verified.

        """
        return self.URI_TEMPLATE.format(domain=domain, path=self.path)

    def _fields_to_json(self):
        return {"path": self.path}

    @classmethod
    def from_valid_json(cls, jobj):
        return cls(path=jobj["path"])


@Challenge.register
class DVSNI(DVChallenge):
    """ACME "dvsni" challenge.

    :ivar str r: Random data, **not** base64-encoded.
    :ivar str nonce: Random data, **not** hex-encoded.

    """
    acme_type = "dvsni"
    __slots__ = ("r", "nonce")

    DOMAIN_SUFFIX = ".acme.invalid"
    """Domain name suffix."""

    R_SIZE = 32
    """Required size of the :attr:`r` in bytes."""

    NONCE_SIZE = 16
    """Required size of the :attr:`nonce` in bytes."""

    @property
    def nonce_domain(self):
        """Domain name used in SNI."""
        return binascii.hexlify(self.nonce) + self.DOMAIN_SUFFIX

    def _fields_to_json(self):
        return {
            "r": jose.b64encode(self.r),
            "nonce": binascii.hexlify(self.nonce),
        }

    @classmethod
    def from_valid_json(cls, jobj):
        return cls(r=util.decode_b64jose(jobj["r"], cls.R_SIZE),
                   nonce=util.decode_hex16(jobj["nonce"], cls.NONCE_SIZE))


@ChallengeResponse.register
class DVSNIResponse(ChallengeResponse):
    """ACME "dvsni" challenge response.

    :param str s: Random data, **not** base64-encoded.

    """
    acme_type = "dvsni"
    __slots__ = ("s",)

    DOMAIN_SUFFIX = DVSNI.DOMAIN_SUFFIX
    """Domain name suffix."""

    S_SIZE = 32
    """Required size of the :attr:`s` in bytes."""

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

    def _fields_to_json(self):
        return {"s": jose.b64encode(self.s)}

    @classmethod
    def from_valid_json(cls, jobj):
        return cls(s=util.decode_b64jose(jobj["s"], cls.S_SIZE))


@Challenge.register
class RecoveryContact(ClientChallenge):
    """ACME "recoveryContact" challenge."""
    acme_type = "recoveryContact"
    __slots__ = ("activation_url", "success_url", "contact")

    def _fields_to_json(self):
        fields = {}
        add = functools.partial(_extend_if_not_none, fields)
        add(self.activation_url, "activationURL")
        add(self.success_url, "successURL")
        add(self.contact, "contact")
        return fields

    @classmethod
    def from_valid_json(cls, jobj):
        return cls(activation_url=jobj.get("activationURL"),
                   success_url=jobj.get("successURL"),
                   contact=jobj.get("contact"))


@ChallengeResponse.register
class RecoveryContactResponse(ChallengeResponse):
    """ACME "recoveryContact" challenge response."""
    acme_type = "recoveryContact"
    __slots__ = ("token",)

    def _fields_to_json(self):
        fields = {}
        if self.token is not None:
            fields["token"] = self.token
        return fields

    @classmethod
    def from_valid_json(cls, jobj):
        return cls(token=jobj.get("token"))


@Challenge.register
class RecoveryToken(ClientChallenge):
    """ACME "recoveryToken" challenge."""
    acme_type = "recoveryToken"
    __slots__ = ()

    def _fields_to_json(self):
        return {}

    @classmethod
    def from_valid_json(cls, jobj):
        return cls()


@ChallengeResponse.register
class RecoveryTokenResponse(ChallengeResponse):
    """ACME "recoveryToken" challenge response."""
    acme_type = "recoveryToken"
    __slots__ = ("token",)

    def _fields_to_json(self):
        fields = {}
        if self.token is not None:
            fields["token"] = self.token
        return fields

    @classmethod
    def from_valid_json(cls, jobj):
        return cls(token=jobj.get("token"))


def _extend_if_not_empty(dikt, param, name):
    if param:
        dikt[name] = param

def _extend_if_not_none(dikt, param, name):
    if param is not None:
        dikt[name] = param


@Challenge.register
class ProofOfPossession(ClientChallenge):
    """ACME "proofOfPossession" challenge.

    :ivar str nonce: Random data, **not** base64-encoded.
    :ivar hints: Various clues for the client (:class:`Hints`).

    """
    acme_type = "proofOfPossession"
    __slots__ = ("alg", "nonce", "hints")

    NONCE_SIZE = 16

    class Hints(util.ACMEObject):
        """Hints for "proofOfPossession" challenge.

        :ivar jwk: JSON Web Key (:class:`letsencrypt.acme.other.JWK`)
        :ivar list certs: List of :class:`M2Crypto.X509.X509` cetificates.

        """
        __slots__ = (
            "jwk", "cert_fingerprints", "certs", "subject_key_identifiers",
            "serial_numbers", "issuers", "authorized_for")

        def to_json(self):
            fields = {"jwk": self.jwk}
            add = functools.partial(_extend_if_not_empty, fields)
            add(self.cert_fingerprints, "certFingerprints")
            add([util.encode_cert(cert) for cert in self.certs], "certs")
            add(self.subject_key_identifiers, "subjectKeyIdentifiers")
            add(self.serial_numbers, "serialNumbers")
            add(self.issuers, "issuers")
            add(self.authorized_for, "authorizedFor")
            return fields

        @classmethod
        def from_valid_json(cls, jobj):
            return cls(
                jwk=other.JWK.from_valid_json(jobj["jwk"]),
                cert_fingerprints=jobj.get("certFingerprints", []),
                certs=[util.decode_cert(cert)
                       for cert in jobj.get("certs", [])],
                subject_key_identifiers=jobj.get("subjectKeyIdentifiers", []),
                serial_numbers=jobj.get("serialNumbers", []),
                issuers=jobj.get("issuers", []),
                authorized_for=jobj.get("authorizedFor", []))

    def _fields_to_json(self):
        return {
            "alg": self.alg,
            "nonce": jose.b64encode(self.nonce),
            "hints": self.hints,
        }

    @classmethod
    def from_valid_json(cls, jobj):
        return cls(alg=jobj["alg"],
                   nonce=util.decode_b64jose(jobj["nonce"], cls.NONCE_SIZE),
                   hints=cls.Hints.from_valid_json(jobj["hints"]))


@ChallengeResponse.register
class ProofOfPossessionResponse(ChallengeResponse):
    """ACME "proofOfPossession" challenge response.

    :ivar str nonce: Random data, **not** base64-encoded.
    :ivar signature: :class:`~letsencrypt.acme.other.Signature` of this message.

    """
    acme_type = "proofOfPossession"
    __slots__ = ("nonce", "signature")

    NONCE_SIZE = ProofOfPossession.NONCE_SIZE

    def verify(self):
        """Verify the challenge."""
        return self.signature.verify(self.nonce)

    def _fields_to_json(self):
        return {
            "nonce": jose.b64encode(self.nonce),
            "signature": self.signature,
        }

    @classmethod
    def from_valid_json(cls, jobj):
        return cls(nonce=util.decode_b64jose(jobj["nonce"], cls.NONCE_SIZE),
                   signature=other.Signature.from_valid_json(jobj["signature"]))


@Challenge.register
class DNS(DVChallenge):
    """ACME "dns" challenge."""
    acme_type = "dns"
    __slots__ = ("token",)

    def _fields_to_json(self):
        return {"token": self.token}

    @classmethod
    def from_valid_json(cls, jobj):
        return cls(token=jobj["token"])


@ChallengeResponse.register
class DNSResponse(ChallengeResponse):
    """ACME "dns" challenge response."""
    acme_type = "dns"
    __slots__ = ()

    def _fields_to_json(self):
        return {}

    @classmethod
    def from_valid_json(cls, jobj):
        return cls()
