"""ACME Identifier Validation Challenges."""
import functools
import hashlib
import logging
import socket

import OpenSSL
import requests

from acme import errors
from acme import crypto_util
from acme import fields
from acme import jose
from acme import other


logger = logging.getLogger(__name__)


# pylint: disable=too-few-public-methods


class Challenge(jose.TypedJSONObjectWithFields):
    # _fields_to_partial_json | pylint: disable=abstract-method
    """ACME challenge."""
    TYPES = {}

    @classmethod
    def from_json(cls, jobj):
        try:
            return super(Challenge, cls).from_json(jobj)
        except jose.UnrecognizedTypeError as error:
            logger.debug(error)
            return UnrecognizedChallenge.from_json(jobj)


class ContinuityChallenge(Challenge):  # pylint: disable=abstract-method
    """Client validation challenges."""


class DVChallenge(Challenge):  # pylint: disable=abstract-method
    """Domain validation challenges."""


class ChallengeResponse(jose.TypedJSONObjectWithFields):
    # _fields_to_partial_json | pylint: disable=abstract-method
    """ACME challenge response."""
    TYPES = {}
    resource_type = 'challenge'
    resource = fields.Resource(resource_type)


class UnrecognizedChallenge(Challenge):
    """Unrecognized challenge.

    ACME specification defines a generic framework for challenges and
    defines some standard challenges that are implemented in this
    module. However, other implementations (including peers) might
    define additional challenge types, which should be ignored if
    unrecognized.

    :ivar jobj: Original JSON decoded object.

    """

    def __init__(self, jobj):
        super(UnrecognizedChallenge, self).__init__()
        object.__setattr__(self, "jobj", jobj)

    def to_partial_json(self):
        # pylint: disable=no-member
        return self.jobj

    @classmethod
    def from_json(cls, jobj):
        return cls(jobj)


@Challenge.register
class SimpleHTTP(DVChallenge):
    """ACME "simpleHttp" challenge.

    :ivar unicode token:

    """
    typ = "simpleHttp"

    TOKEN_SIZE = 128 / 8  # Based on the entropy value from the spec
    """Minimum size of the :attr:`token` in bytes."""

    # TODO: acme-spec doesn't specify token as base64-encoded value
    token = jose.Field(
        "token", encoder=jose.encode_b64jose, decoder=functools.partial(
            jose.decode_b64jose, size=TOKEN_SIZE, minimum=True))

    @property
    def good_token(self):  # XXX: @token.decoder
        """Is `token` good?

        .. todo:: acme-spec wants "It MUST NOT contain any non-ASCII
           characters", but it should also warrant that it doesn't
           contain ".." or "/"...

        """
        # TODO: check that path combined with uri does not go above
        # URI_ROOT_PATH!
        return b'..' not in self.token and b'/' not in self.token


@ChallengeResponse.register
class SimpleHTTPResponse(ChallengeResponse):
    """ACME "simpleHttp" challenge response.

    :ivar bool tls:

    """
    typ = "simpleHttp"
    tls = jose.Field("tls", default=True, omitempty=True)

    URI_ROOT_PATH = ".well-known/acme-challenge"
    """URI root path for the server provisioned resource."""

    _URI_TEMPLATE = "{scheme}://{domain}/" + URI_ROOT_PATH + "/{token}"

    CONTENT_TYPE = "application/jose+json"

    @property
    def scheme(self):
        """URL scheme for the provisioned resource."""
        return "https" if self.tls else "http"

    @property
    def port(self):
        """Port that the ACME client should be listening for validation."""
        return 443 if self.tls else 80

    def uri(self, domain, chall):
        """Create an URI to the provisioned resource.

        Forms an URI to the HTTPS server provisioned resource
        (containing :attr:`~SimpleHTTP.token`).

        :param unicode domain: Domain name being verified.
        :param challenges.SimpleHTTP chall:

        """
        return self._URI_TEMPLATE.format(
            scheme=self.scheme, domain=domain, token=chall.encode("token"))

    def gen_resource(self, chall):
        """Generate provisioned resource.

        :param challenges.SimpleHTTP chall:
        :rtype: SimpleHTTPProvisionedResource

        """
        return SimpleHTTPProvisionedResource(token=chall.token, tls=self.tls)

    def gen_validation(self, chall, account_key, alg=jose.RS256, **kwargs):
        """Generate validation.

        :param challenges.SimpleHTTP chall:
        :param .JWK account_key: Private account key.
        :param .JWA alg:

        :returns: `.SimpleHTTPProvisionedResource` signed in `.JWS`
        :rtype: .JWS

        """
        return jose.JWS.sign(
            payload=self.gen_resource(chall).json_dumps(
                sort_keys=True).encode('utf-8'),
            key=account_key, alg=alg, **kwargs)

    def check_validation(self, validation, chall, account_public_key):
        """Check validation.

        :param .JWS validation:
        :param challenges.SimpleHTTP chall:
        :type account_public_key:
            `~cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey`
            or
            `~cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicKey`
            or
            `~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey`
            wrapped in `.ComparableKey`

        :rtype: bool

        """
        if not validation.verify(key=account_public_key):
            return False

        try:
            resource = SimpleHTTPProvisionedResource.json_loads(
                validation.payload.decode('utf-8'))
        except jose.DeserializationError as error:
            logger.debug(error)
            return False

        return resource.token == chall.token and resource.tls == self.tls

    def simple_verify(self, chall, domain, account_public_key, port=None):
        """Simple verify.

        According to the ACME specification, "the ACME server MUST
        ignore the certificate provided by the HTTPS server", so
        ``requests.get`` is called with ``verify=False``.

        :param challenges.SimpleHTTP chall: Corresponding challenge.
        :param unicode domain: Domain name being verified.
        :param account_public_key: Public key for the key pair
            being authorized. If ``None`` key verification is not
            performed!
        :type account_public_key:
            `~cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey`
            or
            `~cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicKey`
            or
            `~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey`
            wrapped in `.ComparableKey`
        :param int port: Port used in the validation.

        :returns: ``True`` iff validation is successful, ``False``
            otherwise.
        :rtype: bool

        """
        # TODO: ACME specification defines URI template that doesn't
        # allow to use a custom port... Make sure port is not in the
        # request URI, if it's standard.
        if port is not None and port != self.port:
            logger.warn(
                "Using non-standard port for SimpleHTTP verification: %s", port)
            domain += ":{0}".format(port)

        uri = self.uri(domain, chall)
        logger.debug("Verifying %s at %s...", chall.typ, uri)
        try:
            http_response = requests.get(uri, verify=False)
        except requests.exceptions.RequestException as error:
            logger.error("Unable to reach %s: %s", uri, error)
            return False
        logger.debug("Received %s: %s. Headers: %s", http_response,
                     http_response.text, http_response.headers)

        if self.CONTENT_TYPE != http_response.headers.get(
                "Content-Type", self.CONTENT_TYPE):
            return False

        try:
            validation = jose.JWS.json_loads(http_response.text)
        except jose.DeserializationError as error:
            logger.debug(error)
            return False

        return self.check_validation(validation, chall, account_public_key)


class SimpleHTTPProvisionedResource(jose.JSONObjectWithFields):
    """SimpleHTTP provisioned resource."""
    typ = fields.Fixed("type", SimpleHTTP.typ)
    token = SimpleHTTP._fields["token"]
    # If the "tls" field is not included in the response, then
    # validation object MUST have its "tls" field set to "true".
    tls = jose.Field("tls", omitempty=False)


@Challenge.register
class DVSNI(DVChallenge):
    """ACME "dvsni" challenge.

    :ivar bytes token: Random data, **not** base64-encoded.

    """
    typ = "dvsni"

    PORT = 443
    """Port to perform DVSNI challenge."""

    TOKEN_SIZE = 128 / 8  # Based on the entropy value from the spec
    """Minimum size of the :attr:`token` in bytes."""

    token = jose.Field(
        "token", encoder=jose.encode_b64jose, decoder=functools.partial(
            jose.decode_b64jose, size=TOKEN_SIZE, minimum=True))

    def gen_response(self, account_key, alg=jose.RS256, **kwargs):
        """Generate response.

        :param .JWK account_key: Private account key.
        :rtype: .DVSNIResponse

        """
        return DVSNIResponse(validation=jose.JWS.sign(
            payload=self.json_dumps(sort_keys=True).encode('utf-8'),
            key=account_key, alg=alg, **kwargs))


@ChallengeResponse.register
class DVSNIResponse(ChallengeResponse):
    """ACME "dvsni" challenge response.

    :param bytes s: Random data, **not** base64-encoded.

    """
    typ = "dvsni"

    DOMAIN_SUFFIX = b".acme.invalid"
    """Domain name suffix."""

    PORT = DVSNI.PORT
    """Port to perform DVSNI challenge."""

    validation = jose.Field("validation", decoder=jose.JWS.from_json)

    @property
    def z(self):  # pylint: disable=invalid-name
        """The ``z``  parameter.

        :rtype: bytes

        """
        # Instance of 'Field' has no 'signature' member
        # pylint: disable=no-member
        return hashlib.sha256(self.validation.signature.encode(
            "signature").encode("utf-8")).hexdigest().encode()

    @property
    def z_domain(self):
        """Domain name for certificate subjectAltName.

        :rtype: bytes

        """
        z = self.z  # pylint: disable=invalid-name
        return z[:32] + b'.' + z[32:] + self.DOMAIN_SUFFIX

    @property
    def chall(self):
        """Get challenge encoded in the `validation` payload.

        :rtype: challenges.DVSNI

        """
        # pylint: disable=no-member
        return DVSNI.json_loads(self.validation.payload.decode('utf-8'))

    def gen_cert(self, key=None, bits=2048):
        """Generate DVSNI certificate.

        :param OpenSSL.crypto.PKey key: Optional private key used in
            certificate generation. If not provided (``None``), then
            fresh key will be generated.
        :param int bits: Number of bits for newly generated key.

        :rtype: `tuple` of `OpenSSL.crypto.X509` and
            `OpenSSL.crypto.PKey`

        """
        if key is None:
            key = OpenSSL.crypto.PKey()
            key.generate_key(OpenSSL.crypto.TYPE_RSA, bits)
        return crypto_util.gen_ss_cert(key, [
            # z_domain is too big to fit into CN, hence first dummy domain
            'dummy', self.z_domain.decode()], force_san=True), key

    def probe_cert(self, domain, **kwargs):
        """Probe DVSNI challenge certificate.

        :param unicode domain:

        """
        if "host" not in kwargs:
            host = socket.gethostbyname(domain)
            logging.debug('%s resolved to %s', domain, host)
            kwargs["host"] = host

        kwargs.setdefault("port", self.PORT)
        kwargs["name"] = self.z_domain
        # TODO: try different methods?
        # pylint: disable=protected-access
        return crypto_util.probe_sni(**kwargs)

    def verify_cert(self, cert):
        """Verify DVSNI challenge certificate."""
        # pylint: disable=protected-access
        sans = crypto_util._pyopenssl_cert_or_req_san(cert)
        logging.debug('Certificate %s. SANs: %s', cert.digest('sha1'), sans)
        return self.z_domain.decode() in sans

    def simple_verify(self, chall, domain, account_public_key,
                      cert=None, **kwargs):
        """Simple verify.

        Verify ``validation`` using ``account_public_key``, optionally
        probe DVSNI certificate and check using `verify_cert`.

        :param .challenges.DVSNI chall: Corresponding challenge.
        :param str domain: Domain name being validated.
        :type account_public_key:
            `~cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey`
            or
            `~cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicKey`
            or
            `~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey`
            wrapped in `.ComparableKey`
        :param OpenSSL.crypto.X509 cert: Optional certificate. If not
            provided (``None``) certificate will be retrieved using
            `probe_cert`.

        :returns: ``True`` iff client's control of the domain has been
            verified, ``False`` otherwise.
        :rtype: bool

        """
        # pylint: disable=no-member
        if not self.validation.verify(key=account_public_key):
            return False

        # TODO: it's not checked that payload has exectly 2 fields!
        try:
            decoded_chall = self.chall
        except jose.DeserializationError as error:
            logger.debug(error, exc_info=True)
            return False

        if decoded_chall.token != chall.token:
            logger.debug("Wrong token: expected %r, found %r",
                         chall.token, decoded_chall.token)
            return False

        if cert is None:
            try:
                cert = self.probe_cert(domain=domain, **kwargs)
            except errors.Error as error:
                logger.debug(error, exc_info=True)
                return False

        return self.verify_cert(cert)


@Challenge.register
class RecoveryContact(ContinuityChallenge):
    """ACME "recoveryContact" challenge.

    :ivar unicode activation_url:
    :ivar unicode success_url:
    :ivar unicode contact:

    """
    typ = "recoveryContact"

    activation_url = jose.Field("activationURL", omitempty=True)
    success_url = jose.Field("successURL", omitempty=True)
    contact = jose.Field("contact", omitempty=True)


@ChallengeResponse.register
class RecoveryContactResponse(ChallengeResponse):
    """ACME "recoveryContact" challenge response.

    :ivar unicode token:

    """
    typ = "recoveryContact"
    token = jose.Field("token", omitempty=True)


@Challenge.register
class ProofOfPossession(ContinuityChallenge):
    """ACME "proofOfPossession" challenge.

    :ivar .JWAAlgorithm alg:
    :ivar bytes nonce: Random data, **not** base64-encoded.
    :ivar hints: Various clues for the client (:class:`Hints`).

    """
    typ = "proofOfPossession"

    NONCE_SIZE = 16

    class Hints(jose.JSONObjectWithFields):
        """Hints for "proofOfPossession" challenge.

        :ivar jwk: JSON Web Key (:class:`acme.jose.JWK`)
        :ivar tuple cert_fingerprints: `tuple` of `unicode`
        :ivar tuple certs: Sequence of :class:`acme.jose.ComparableX509`
            certificates.
        :ivar tuple subject_key_identifiers: `tuple` of `unicode`
        :ivar tuple issuers: `tuple` of `unicode`
        :ivar tuple authorized_for: `tuple` of `unicode`

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
        "nonce", encoder=jose.encode_b64jose, decoder=functools.partial(
            jose.decode_b64jose, size=NONCE_SIZE))
    hints = jose.Field("hints", decoder=Hints.from_json)


@ChallengeResponse.register
class ProofOfPossessionResponse(ChallengeResponse):
    """ACME "proofOfPossession" challenge response.

    :ivar bytes nonce: Random data, **not** base64-encoded.
    :ivar acme.other.Signature signature: Sugnature of this message.

    """
    typ = "proofOfPossession"

    NONCE_SIZE = ProofOfPossession.NONCE_SIZE

    nonce = jose.Field(
        "nonce", encoder=jose.encode_b64jose, decoder=functools.partial(
            jose.decode_b64jose, size=NONCE_SIZE))
    signature = jose.Field("signature", decoder=other.Signature.from_json)

    def verify(self):
        """Verify the challenge."""
        # self.signature is not Field | pylint: disable=no-member
        return self.signature.verify(self.nonce)


@Challenge.register
class DNS(DVChallenge):
    """ACME "dns" challenge.

    :ivar unicode token:

    """
    typ = "dns"

    LABEL = "_acme-challenge"
    """Label clients prepend to the domain name being validated."""

    TOKEN_SIZE = 128 / 8  # Based on the entropy value from the spec
    """Minimum size of the :attr:`token` in bytes."""

    token = jose.Field(
        "token", encoder=jose.encode_b64jose, decoder=functools.partial(
            jose.decode_b64jose, size=TOKEN_SIZE, minimum=True))

    def gen_validation(self, account_key, alg=jose.RS256, **kwargs):
        """Generate validation.

        :param .JWK account_key: Private account key.
        :param .JWA alg:

        :returns: This challenge wrapped in `.JWS`
        :rtype: .JWS

        """
        return jose.JWS.sign(
            payload=self.json_dumps(sort_keys=True).encode('utf-8'),
            key=account_key, alg=alg, **kwargs)

    def check_validation(self, validation, account_public_key):
        """Check validation.

        :param JWS validation:
        :type account_public_key:
            `~cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey`
            or
            `~cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicKey`
            or
            `~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey`
            wrapped in `.ComparableKey`

        :rtype: bool

        """
        if not validation.verify(key=account_public_key):
            return False
        try:
            return self == self.json_loads(
                validation.payload.decode('utf-8'))
        except jose.DeserializationError as error:
            logger.debug("Checking validation for DNS failed: %s", error)
            return False

    def gen_response(self, account_key, **kwargs):
        """Generate response.

        :param .JWK account_key: Private account key.
        :param .JWA alg:

        :rtype: DNSResponse

        """
        return DNSResponse(validation=self.gen_validation(
            self, account_key, **kwargs))

    def validation_domain_name(self, name):
        """Domain name for TXT validation record.

        :param unicode name: Domain name being validated.

        """
        return "{0}.{1}".format(self.LABEL, name)


@ChallengeResponse.register
class DNSResponse(ChallengeResponse):
    """ACME "dns" challenge response.

    :param JWS validation:

    """
    typ = "dns"

    validation = jose.Field("validation", decoder=jose.JWS.from_json)

    def check_validation(self, chall, account_public_key):
        """Check validation.

        :param challenges.DNS chall:
        :type account_public_key:
            `~cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey`
            or
            `~cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicKey`
            or
            `~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey`
            wrapped in `.ComparableKey`

        :rtype: bool

        """
        return chall.check_validation(self.validation, account_public_key)
