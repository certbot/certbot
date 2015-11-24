"""ACME Identifier Validation Challenges."""
import abc
import functools
import hashlib
import logging
import socket

from cryptography.hazmat.primitives import hashes
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


class _TokenDVChallenge(DVChallenge):
    """DV Challenge with token.

    :ivar bytes token:

    """
    TOKEN_SIZE = 128 / 8  # Based on the entropy value from the spec
    """Minimum size of the :attr:`token` in bytes."""

    # TODO: acme-spec doesn't specify token as base64-encoded value
    token = jose.Field(
        "token", encoder=jose.encode_b64jose, decoder=functools.partial(
            jose.decode_b64jose, size=TOKEN_SIZE, minimum=True))

    # XXX: rename to ~token_good_for_url
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


class KeyAuthorizationChallengeResponse(ChallengeResponse):
    """Response to Challenges based on Key Authorization.

    :param unicode key_authorization:

    """
    key_authorization = jose.Field("keyAuthorization")
    thumbprint_hash_function = hashes.SHA256

    def verify(self, chall, account_public_key):
        """Verify the key authorization.

        :param KeyAuthorization chall: Challenge that corresponds to
            this response.
        :param JWK account_public_key:

        :return: ``True`` iff verification of the key authorization was
            successful.
        :rtype: bool

        """
        parts = self.key_authorization.split('.')  # pylint: disable=no-member
        if len(parts) != 2:
            logger.debug("Key authorization (%r) is not well formed",
                         self.key_authorization)
            return False

        if parts[0] != chall.encode("token"):
            logger.debug("Mismatching token in key authorization: "
                         "%r instead of %r", parts[0], chall.encode("token"))
            return False

        thumbprint = jose.b64encode(account_public_key.thumbprint(
            hash_function=self.thumbprint_hash_function)).decode()
        if parts[1] != thumbprint:
            logger.debug("Mismatching thumbprint in key authorization: "
                         "%r instead of %r", parts[0], thumbprint)
            return False

        return True


class KeyAuthorizationChallenge(_TokenDVChallenge):
    # pylint: disable=abstract-class-little-used,too-many-ancestors
    """Challenge based on Key Authorization.

    :param response_cls: Subclass of `KeyAuthorizationChallengeResponse`
        that will be used to generate `response`.

    """
    __metaclass__ = abc.ABCMeta

    response_cls = NotImplemented
    thumbprint_hash_function = (
        KeyAuthorizationChallengeResponse.thumbprint_hash_function)

    def key_authorization(self, account_key):
        """Generate Key Authorization.

        :param JWK account_key:
        :rtype unicode:

        """
        return self.encode("token") + "." + jose.b64encode(
            account_key.thumbprint(
                hash_function=self.thumbprint_hash_function)).decode()

    def response(self, account_key):
        """Generate response to the challenge.

        :param JWK account_key:

        :returns: Response (initialized `response_cls`) to the challenge.
        :rtype: KeyAuthorizationChallengeResponse

        """
        return self.response_cls(
            key_authorization=self.key_authorization(account_key))

    @abc.abstractmethod
    def validation(self, account_key, **kwargs):
        """Generate validation for the challenge.

        Subclasses must implement this method, but they are likely to
        return completely different data structures, depending on what's
        necessary to complete the challenge. Interepretation of that
        return value must be known to the caller.

        :param JWK account_key:
        :returns: Challenge-specific validation.

        """
        raise NotImplementedError()  # pragma: no cover

    def response_and_validation(self, account_key, *args, **kwargs):
        """Generate response and validation.

        Convenience function that return results of `response` and
        `validation`.

        :param JWK account_key:
        :rtype: tuple

        """
        return (self.response(account_key),
                self.validation(account_key, *args, **kwargs))


@ChallengeResponse.register
class HTTP01Response(KeyAuthorizationChallengeResponse):
    """ACME http-01 challenge response."""
    typ = "http-01"

    PORT = 80
    """Verification port as defined by the protocol.

    You can override it (e.g. for testing) by passing ``port`` to
    `simple_verify`.

    """

    WHITESPACE_CUTSET = "\n\r\t "
    """Whitespace characters which should be ignored at the end of the body."""

    def simple_verify(self, chall, domain, account_public_key, port=None):
        """Simple verify.

        :param challenges.SimpleHTTP chall: Corresponding challenge.
        :param unicode domain: Domain name being verified.
        :param account_public_key: Public key for the key pair
            being authorized. If ``None`` key verification is not
            performed!
        :param JWK account_public_key:
        :param int port: Port used in the validation.

        :returns: ``True`` iff validation is successful, ``False``
            otherwise.
        :rtype: bool

        """
        if not self.verify(chall, account_public_key):
            logger.debug("Verification of key authorization in response failed")
            return False

        # TODO: ACME specification defines URI template that doesn't
        # allow to use a custom port... Make sure port is not in the
        # request URI, if it's standard.
        if port is not None and port != self.PORT:
            logger.warning(
                "Using non-standard port for http-01 verification: %s", port)
            domain += ":{0}".format(port)

        uri = chall.uri(domain)
        logger.debug("Verifying %s at %s...", chall.typ, uri)
        try:
            http_response = requests.get(uri)
        except requests.exceptions.RequestException as error:
            logger.error("Unable to reach %s: %s", uri, error)
            return False
        logger.debug("Received %s: %s. Headers: %s", http_response,
                     http_response.text, http_response.headers)

        challenge_response = http_response.text.rstrip(self.WHITESPACE_CUTSET)
        if self.key_authorization != challenge_response:
            logger.debug("Key authorization from response (%r) doesn't match "
                         "HTTP response (%r)", self.key_authorization,
                         challenge_response)
            return False

        return True


@Challenge.register  # pylint: disable=too-many-ancestors
class HTTP01(KeyAuthorizationChallenge):
    """ACME http-01 challenge."""
    response_cls = HTTP01Response
    typ = response_cls.typ

    URI_ROOT_PATH = ".well-known/acme-challenge"
    """URI root path for the server provisioned resource."""

    @property
    def path(self):
        """Path (starting with '/') for provisioned resource.

        :rtype: string

        """
        return '/' + self.URI_ROOT_PATH + '/' + self.encode('token')

    def uri(self, domain):
        """Create an URI to the provisioned resource.

        Forms an URI to the HTTPS server provisioned resource
        (containing :attr:`~SimpleHTTP.token`).

        :param unicode domain: Domain name being verified.
        :rtype: string

        """
        return "http://" + domain + self.path

    def validation(self, account_key, **unused_kwargs):
        """Generate validation.

        :param JWK account_key:
        :rtype: unicode

        """
        return self.key_authorization(account_key)


@ChallengeResponse.register
class TLSSNI01Response(KeyAuthorizationChallengeResponse):
    """ACME tls-sni-01 challenge response."""
    typ = "tls-sni-01"

    DOMAIN_SUFFIX = b".acme.invalid"
    """Domain name suffix."""

    PORT = 443
    """Verification port as defined by the protocol.

    You can override it (e.g. for testing) by passing ``port`` to
    `simple_verify`.

    """

    @property
    def z(self):
        """``z`` value used for verification.

        :rtype bytes:

        """
        return hashlib.sha256(
            self.key_authorization.encode("utf-8")).hexdigest().lower().encode()

    @property
    def z_domain(self):
        """Domain name used for verification, generated from `z`.

        :rtype bytes:

        """
        return self.z[:32] + b'.' + self.z[32:] + self.DOMAIN_SUFFIX

    def gen_cert(self, key=None, bits=2048):
        """Generate tls-sni-01 certificate.

        :param OpenSSL.crypto.PKey key: Optional private key used in
            certificate generation. If not provided (``None``), then
            fresh key will be generated.
        :param int bits: Number of bits for newly generated key.

        :rtype: `tuple` of `OpenSSL.crypto.X509` and `OpenSSL.crypto.PKey`

        """
        if key is None:
            key = OpenSSL.crypto.PKey()
            key.generate_key(OpenSSL.crypto.TYPE_RSA, bits)
        return crypto_util.gen_ss_cert(key, [
            # z_domain is too big to fit into CN, hence first dummy domain
            'dummy', self.z_domain.decode()], force_san=True), key

    def probe_cert(self, domain, **kwargs):
        """Probe tls-sni-01 challenge certificate.

        :param unicode domain:

        """
        # TODO: domain is not necessary if host is provided
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
        """Verify tls-sni-01 challenge certificate."""
        # pylint: disable=protected-access
        sans = crypto_util._pyopenssl_cert_or_req_san(cert)
        logging.debug('Certificate %s. SANs: %s', cert.digest('sha1'), sans)
        return self.z_domain.decode() in sans

    def simple_verify(self, chall, domain, account_public_key,
                      cert=None, **kwargs):
        """Simple verify.

        Verify ``validation`` using ``account_public_key``, optionally
        probe tls-sni-01 certificate and check using `verify_cert`.

        :param .challenges.TLSSNI01 chall: Corresponding challenge.
        :param str domain: Domain name being validated.
        :param JWK account_public_key:
        :param OpenSSL.crypto.X509 cert: Optional certificate. If not
            provided (``None``) certificate will be retrieved using
            `probe_cert`.
        :param int port: Port used to probe the certificate.


        :returns: ``True`` iff client's control of the domain has been
            verified, ``False`` otherwise.
        :rtype: bool

        """
        if not self.verify(chall, account_public_key):
            logger.debug("Verification of key authorization in response failed")
            return False

        if cert is None:
            try:
                cert = self.probe_cert(domain=domain, **kwargs)
            except errors.Error as error:
                logger.debug(error, exc_info=True)
                return False

        return self.verify_cert(cert)


@Challenge.register  # pylint: disable=too-many-ancestors
class TLSSNI01(KeyAuthorizationChallenge):
    """ACME tls-sni-01 challenge."""
    response_cls = TLSSNI01Response
    typ = response_cls.typ

    # boulder#962, ietf-wg-acme#22
    #n = jose.Field("n", encoder=int, decoder=int)

    def validation(self, account_key, **kwargs):
        """Generate validation.

        :param JWK account_key:
        :param OpenSSL.crypto.PKey cert_key: Optional private key used
            in certificate generation. If not provided (``None``), then
            fresh key will be generated.

        :rtype: `tuple` of `OpenSSL.crypto.X509` and `OpenSSL.crypto.PKey`

        """
        return self.response(account_key).gen_cert(key=kwargs.get('cert_key'))


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

        :ivar JWK jwk: JSON Web Key
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


@Challenge.register  # pylint: disable=too-many-ancestors
class DNS(_TokenDVChallenge):
    """ACME "dns" challenge."""
    typ = "dns"

    LABEL = "_acme-challenge"
    """Label clients prepend to the domain name being validated."""

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
        :param JWK account_public_key:
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
        :param JWK account_public_key:

        :rtype: bool

        """
        return chall.check_validation(self.validation, account_public_key)
