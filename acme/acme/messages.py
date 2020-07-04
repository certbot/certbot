"""ACME protocol messages."""
import json

import josepy as jose
import six

from acme import challenges
from acme import errors
from acme import fields
from acme import jws
from acme import util
from acme.mixins import ResourceMixin

try:
    from collections.abc import Hashable
except ImportError:  # pragma: no cover
    from collections import Hashable



OLD_ERROR_PREFIX = "urn:acme:error:"
ERROR_PREFIX = "urn:ietf:params:acme:error:"

ERROR_CODES = {
    'accountDoesNotExist': 'The request specified an account that does not exist',
    'alreadyRevoked': 'The request specified a certificate to be revoked that has' \
    ' already been revoked',
    'badCSR': 'The CSR is unacceptable (e.g., due to a short key)',
    'badNonce': 'The client sent an unacceptable anti-replay nonce',
    'badPublicKey': 'The JWS was signed by a public key the server does not support',
    'badRevocationReason': 'The revocation reason provided is not allowed by the server',
    'badSignatureAlgorithm': 'The JWS was signed with an algorithm the server does not support',
    'caa': 'Certification Authority Authorization (CAA) records forbid the CA from issuing' \
    ' a certificate',
    'compound': 'Specific error conditions are indicated in the "subproblems" array',
    'connection': ('The server could not connect to the client to verify the'
                   ' domain'),
    'dns': 'There was a problem with a DNS query during identifier validation',
    'dnssec': 'The server could not validate a DNSSEC signed domain',
    'incorrectResponse': 'Response received didn\'t match the challenge\'s requirements',
    # deprecate invalidEmail
    'invalidEmail': 'The provided email for a registration was invalid',
    'invalidContact': 'The provided contact URI was invalid',
    'malformed': 'The request message was malformed',
    'rejectedIdentifier': 'The server will not issue certificates for the identifier',
    'orderNotReady': 'The request attempted to finalize an order that is not ready to be finalized',
    'rateLimited': 'There were too many requests of a given type',
    'serverInternal': 'The server experienced an internal error',
    'tls': 'The server experienced a TLS error during domain verification',
    'unauthorized': 'The client lacks sufficient authorization',
    'unsupportedContact': 'A contact URL for an account used an unsupported protocol scheme',
    'unknownHost': 'The server could not resolve a domain name',
    'unsupportedIdentifier': 'An identifier is of an unsupported type',
    'externalAccountRequired': 'The server requires external account binding',
}

ERROR_TYPE_DESCRIPTIONS = dict(
    (ERROR_PREFIX + name, desc) for name, desc in ERROR_CODES.items())

ERROR_TYPE_DESCRIPTIONS.update(dict(  # add errors with old prefix, deprecate me
    (OLD_ERROR_PREFIX + name, desc) for name, desc in ERROR_CODES.items()))


def is_acme_error(err):
    """Check if argument is an ACME error."""
    if isinstance(err, Error) and (err.typ is not None):
        return (ERROR_PREFIX in err.typ) or (OLD_ERROR_PREFIX in err.typ)
    return False


@six.python_2_unicode_compatible
class Error(jose.JSONObjectWithFields, errors.Error):
    """ACME error.

    https://tools.ietf.org/html/draft-ietf-appsawg-http-problem-00

    :ivar unicode typ:
    :ivar unicode title:
    :ivar unicode detail:

    """
    typ = jose.Field('type', omitempty=True, default='about:blank')
    title = jose.Field('title', omitempty=True)
    detail = jose.Field('detail', omitempty=True)

    @classmethod
    def with_code(cls, code, **kwargs):
        """Create an Error instance with an ACME Error code.

        :unicode code: An ACME error code, like 'dnssec'.
        :kwargs: kwargs to pass to Error.

        """
        if code not in ERROR_CODES:
            raise ValueError("The supplied code: %s is not a known ACME error"
                             " code" % code)
        typ = ERROR_PREFIX + code
        return cls(typ=typ, **kwargs)

    @property
    def description(self):
        """Hardcoded error description based on its type.

        :returns: Description if standard ACME error or ``None``.
        :rtype: unicode

        """
        return ERROR_TYPE_DESCRIPTIONS.get(self.typ)

    @property
    def code(self):
        """ACME error code.

        Basically self.typ without the ERROR_PREFIX.

        :returns: error code if standard ACME code or ``None``.
        :rtype: unicode

        """
        code = str(self.typ).split(':')[-1]
        if code in ERROR_CODES:
            return code
        return None

    def __str__(self):
        return b' :: '.join(
            part.encode('ascii', 'backslashreplace') for part in
            (self.typ, self.description, self.detail, self.title)
            if part is not None).decode()


class _Constant(jose.JSONDeSerializable, Hashable):  # type: ignore
    """ACME constant."""
    __slots__ = ('name',)
    POSSIBLE_NAMES = NotImplemented

    def __init__(self, name):
        super(_Constant, self).__init__()
        self.POSSIBLE_NAMES[name] = self  # pylint: disable=unsupported-assignment-operation
        self.name = name

    def to_partial_json(self):
        return self.name

    @classmethod
    def from_json(cls, jobj):
        if jobj not in cls.POSSIBLE_NAMES:  # pylint: disable=unsupported-membership-test
            raise jose.DeserializationError(
                '{0} not recognized'.format(cls.__name__))
        return cls.POSSIBLE_NAMES[jobj]

    def __repr__(self):
        return '{0}({1})'.format(self.__class__.__name__, self.name)

    def __eq__(self, other):
        return isinstance(other, type(self)) and other.name == self.name

    def __hash__(self):
        return hash((self.__class__, self.name))

    def __ne__(self, other):
        return not self == other


class Status(_Constant):
    """ACME "status" field."""
    POSSIBLE_NAMES = {}  # type: dict
STATUS_UNKNOWN = Status('unknown')
STATUS_PENDING = Status('pending')
STATUS_PROCESSING = Status('processing')
STATUS_VALID = Status('valid')
STATUS_INVALID = Status('invalid')
STATUS_REVOKED = Status('revoked')
STATUS_READY = Status('ready')
STATUS_DEACTIVATED = Status('deactivated')


class IdentifierType(_Constant):
    """ACME identifier type."""
    POSSIBLE_NAMES = {}  # type: dict
IDENTIFIER_FQDN = IdentifierType('dns')  # IdentifierDNS in Boulder


class Identifier(jose.JSONObjectWithFields):
    """ACME identifier.

    :ivar IdentifierType typ:
    :ivar unicode value:

    """
    typ = jose.Field('type', decoder=IdentifierType.from_json)
    value = jose.Field('value')


class Directory(jose.JSONDeSerializable):
    """Directory."""

    _REGISTERED_TYPES = {}  # type: dict

    class Meta(jose.JSONObjectWithFields):
        """Directory Meta."""
        _terms_of_service = jose.Field('terms-of-service', omitempty=True)
        _terms_of_service_v2 = jose.Field('termsOfService', omitempty=True)
        website = jose.Field('website', omitempty=True)
        caa_identities = jose.Field('caaIdentities', omitempty=True)
        external_account_required = jose.Field('externalAccountRequired', omitempty=True)

        def __init__(self, **kwargs):
            kwargs = dict((self._internal_name(k), v) for k, v in kwargs.items())
            super(Directory.Meta, self).__init__(**kwargs)

        @property
        def terms_of_service(self):
            """URL for the CA TOS"""
            return self._terms_of_service or self._terms_of_service_v2

        def __iter__(self):
            # When iterating over fields, use the external name 'terms_of_service' instead of
            # the internal '_terms_of_service'.
            for name in super(Directory.Meta, self).__iter__():
                yield name[1:] if name == '_terms_of_service' else name

        def _internal_name(self, name):
            return '_' + name if name == 'terms_of_service' else name


    @classmethod
    def _canon_key(cls, key):
        return getattr(key, 'resource_type', key)

    @classmethod
    def register(cls, resource_body_cls):
        """Register resource."""
        resource_type = resource_body_cls.resource_type
        assert resource_type not in cls._REGISTERED_TYPES
        cls._REGISTERED_TYPES[resource_type] = resource_body_cls
        return resource_body_cls

    def __init__(self, jobj):
        canon_jobj = util.map_keys(jobj, self._canon_key)
        # TODO: check that everything is an absolute URL; acme-spec is
        # not clear on that
        self._jobj = canon_jobj

    def __getattr__(self, name):
        try:
            return self[name.replace('_', '-')]
        except KeyError as error:
            raise AttributeError(str(error))

    def __getitem__(self, name):
        try:
            return self._jobj[self._canon_key(name)]
        except KeyError:
            raise KeyError('Directory field "' + self._canon_key(name) + '" not found')

    def to_partial_json(self):
        return self._jobj

    @classmethod
    def from_json(cls, jobj):
        jobj['meta'] = cls.Meta.from_json(jobj.pop('meta', {}))
        return cls(jobj)


class Resource(jose.JSONObjectWithFields):
    """ACME Resource.

    :ivar acme.messages.ResourceBody body: Resource body.

    """
    body = jose.Field('body')


class ResourceWithURI(Resource):
    """ACME Resource with URI.

    :ivar unicode uri: Location of the resource.

    """
    uri = jose.Field('uri')  # no ChallengeResource.uri


class ResourceBody(jose.JSONObjectWithFields):
    """ACME Resource Body."""


class ExternalAccountBinding(object):
    """ACME External Account Binding"""

    @classmethod
    def from_data(cls, account_public_key, kid, hmac_key, directory):
        """Create External Account Binding Resource from contact details, kid and hmac."""

        key_json = json.dumps(account_public_key.to_partial_json()).encode()
        decoded_hmac_key = jose.b64.b64decode(hmac_key)
        url = directory["newAccount"]

        eab = jws.JWS.sign(key_json, jose.jwk.JWKOct(key=decoded_hmac_key),
                           jose.jwa.HS256, None,
                           url, kid)

        return eab.to_partial_json()


class Registration(ResourceBody):
    """Registration Resource Body.

    :ivar josepy.jwk.JWK key: Public key.
    :ivar tuple contact: Contact information following ACME spec,
        `tuple` of `unicode`.
    :ivar unicode agreement:

    """
    # on new-reg key server ignores 'key' and populates it based on
    # JWS.signature.combined.jwk
    key = jose.Field('key', omitempty=True, decoder=jose.JWK.from_json)
    contact = jose.Field('contact', omitempty=True, default=())
    agreement = jose.Field('agreement', omitempty=True)
    status = jose.Field('status', omitempty=True)
    terms_of_service_agreed = jose.Field('termsOfServiceAgreed', omitempty=True)
    only_return_existing = jose.Field('onlyReturnExisting', omitempty=True)
    external_account_binding = jose.Field('externalAccountBinding', omitempty=True)

    phone_prefix = 'tel:'
    email_prefix = 'mailto:'

    @classmethod
    def from_data(cls, phone=None, email=None, external_account_binding=None, **kwargs):
        """Create registration resource from contact details."""
        details = list(kwargs.pop('contact', ()))
        if phone is not None:
            details.append(cls.phone_prefix + phone)
        if email is not None:
            details.extend([cls.email_prefix + mail for mail in email.split(',')])
        kwargs['contact'] = tuple(details)

        if external_account_binding:
            kwargs['external_account_binding'] = external_account_binding

        return cls(**kwargs)

    def _filter_contact(self, prefix):
        return tuple(
            detail[len(prefix):] for detail in self.contact  # pylint: disable=not-an-iterable
            if detail.startswith(prefix))

    @property
    def phones(self):
        """All phones found in the ``contact`` field."""
        return self._filter_contact(self.phone_prefix)

    @property
    def emails(self):
        """All emails found in the ``contact`` field."""
        return self._filter_contact(self.email_prefix)


@Directory.register
class NewRegistration(ResourceMixin, Registration):
    """New registration."""
    resource_type = 'new-reg'
    resource = fields.Resource(resource_type)


class UpdateRegistration(ResourceMixin, Registration):
    """Update registration."""
    resource_type = 'reg'
    resource = fields.Resource(resource_type)


class RegistrationResource(ResourceWithURI):
    """Registration Resource.

    :ivar acme.messages.Registration body:
    :ivar unicode new_authzr_uri: Deprecated. Do not use.
    :ivar unicode terms_of_service: URL for the CA TOS.

    """
    body = jose.Field('body', decoder=Registration.from_json)
    new_authzr_uri = jose.Field('new_authzr_uri', omitempty=True)
    terms_of_service = jose.Field('terms_of_service', omitempty=True)


class ChallengeBody(ResourceBody):
    """Challenge Resource Body.

    .. todo::
       Confusingly, this has a similar name to `.challenges.Challenge`,
       as well as `.achallenges.AnnotatedChallenge`. Please use names
       such as ``challb`` to distinguish instances of this class from
       ``achall``.

    :ivar acme.challenges.Challenge: Wrapped challenge.
        Conveniently, all challenge fields are proxied, i.e. you can
        call ``challb.x`` to get ``challb.chall.x`` contents.
    :ivar acme.messages.Status status:
    :ivar datetime.datetime validated:
    :ivar messages.Error error:

    """
    __slots__ = ('chall',)
    # ACMEv1 has a "uri" field in challenges. ACMEv2 has a "url" field. This
    # challenge object supports either one, but should be accessed through the
    # name "uri". In Client.answer_challenge, whichever one is set will be
    # used.
    _uri = jose.Field('uri', omitempty=True, default=None)
    _url = jose.Field('url', omitempty=True, default=None)
    status = jose.Field('status', decoder=Status.from_json,
                        omitempty=True, default=STATUS_PENDING)
    validated = fields.RFC3339Field('validated', omitempty=True)
    error = jose.Field('error', decoder=Error.from_json,
                       omitempty=True, default=None)

    def __init__(self, **kwargs):
        kwargs = dict((self._internal_name(k), v) for k, v in kwargs.items())
        super(ChallengeBody, self).__init__(**kwargs)

    def encode(self, name):
        return super(ChallengeBody, self).encode(self._internal_name(name))

    def to_partial_json(self):
        jobj = super(ChallengeBody, self).to_partial_json()
        jobj.update(self.chall.to_partial_json())
        return jobj

    @classmethod
    def fields_from_json(cls, jobj):
        jobj_fields = super(ChallengeBody, cls).fields_from_json(jobj)
        jobj_fields['chall'] = challenges.Challenge.from_json(jobj)
        return jobj_fields

    @property
    def uri(self):
        """The URL of this challenge."""
        return self._url or self._uri

    def __getattr__(self, name):
        return getattr(self.chall, name)

    def __iter__(self):
        # When iterating over fields, use the external name 'uri' instead of
        # the internal '_uri'.
        for name in super(ChallengeBody, self).__iter__():
            yield name[1:] if name == '_uri' else name

    def _internal_name(self, name):
        return '_' + name if name == 'uri' else name


class ChallengeResource(Resource):
    """Challenge Resource.

    :ivar acme.messages.ChallengeBody body:
    :ivar unicode authzr_uri: URI found in the 'up' ``Link`` header.

    """
    body = jose.Field('body', decoder=ChallengeBody.from_json)
    authzr_uri = jose.Field('authzr_uri')

    @property
    def uri(self):
        """The URL of the challenge body."""
        return self.body.uri


class Authorization(ResourceBody):
    """Authorization Resource Body.

    :ivar acme.messages.Identifier identifier:
    :ivar list challenges: `list` of `.ChallengeBody`
    :ivar tuple combinations: Challenge combinations (`tuple` of `tuple`
        of `int`, as opposed to `list` of `list` from the spec).
    :ivar acme.messages.Status status:
    :ivar datetime.datetime expires:

    """
    identifier = jose.Field('identifier', decoder=Identifier.from_json, omitempty=True)
    challenges = jose.Field('challenges', omitempty=True)
    combinations = jose.Field('combinations', omitempty=True)

    status = jose.Field('status', omitempty=True, decoder=Status.from_json)
    # TODO: 'expires' is allowed for Authorization Resources in
    # general, but for Key Authorization '[t]he "expires" field MUST
    # be absent'... then acme-spec gives example with 'expires'
    # present... That's confusing!
    expires = fields.RFC3339Field('expires', omitempty=True)
    wildcard = jose.Field('wildcard', omitempty=True)

    @challenges.decoder
    def challenges(value):  # pylint: disable=no-self-argument,missing-function-docstring
        return tuple(ChallengeBody.from_json(chall) for chall in value)

    @property
    def resolved_combinations(self):
        """Combinations with challenges instead of indices."""
        return tuple(tuple(self.challenges[idx] for idx in combo)
                     for combo in self.combinations)  # pylint: disable=not-an-iterable


@Directory.register
class NewAuthorization(ResourceMixin, Authorization):
    """New authorization."""
    resource_type = 'new-authz'
    resource = fields.Resource(resource_type)


class UpdateAuthorization(ResourceMixin, Authorization):
    """Update authorization."""
    resource_type = 'authz'
    resource = fields.Resource(resource_type)


class AuthorizationResource(ResourceWithURI):
    """Authorization Resource.

    :ivar acme.messages.Authorization body:
    :ivar unicode new_cert_uri: Deprecated. Do not use.

    """
    body = jose.Field('body', decoder=Authorization.from_json)
    new_cert_uri = jose.Field('new_cert_uri', omitempty=True)


@Directory.register
class CertificateRequest(ResourceMixin, jose.JSONObjectWithFields):
    """ACME new-cert request.

    :ivar josepy.util.ComparableX509 csr:
        `OpenSSL.crypto.X509Req` wrapped in `.ComparableX509`

    """
    resource_type = 'new-cert'
    resource = fields.Resource(resource_type)
    csr = jose.Field('csr', decoder=jose.decode_csr, encoder=jose.encode_csr)


class CertificateResource(ResourceWithURI):
    """Certificate Resource.

    :ivar josepy.util.ComparableX509 body:
        `OpenSSL.crypto.X509` wrapped in `.ComparableX509`
    :ivar unicode cert_chain_uri: URI found in the 'up' ``Link`` header
    :ivar tuple authzrs: `tuple` of `AuthorizationResource`.

    """
    cert_chain_uri = jose.Field('cert_chain_uri')
    authzrs = jose.Field('authzrs')


@Directory.register
class Revocation(ResourceMixin, jose.JSONObjectWithFields):
    """Revocation message.

    :ivar .ComparableX509 certificate: `OpenSSL.crypto.X509` wrapped in
        `.ComparableX509`

    """
    resource_type = 'revoke-cert'
    resource = fields.Resource(resource_type)
    certificate = jose.Field(
        'certificate', decoder=jose.decode_cert, encoder=jose.encode_cert)
    reason = jose.Field('reason')


class Order(ResourceBody):
    """Order Resource Body.

    :ivar identifiers: List of identifiers for the certificate.
    :vartype identifiers: `list` of `.Identifier`
    :ivar acme.messages.Status status:
    :ivar authorizations: URLs of authorizations.
    :vartype authorizations: `list` of `str`
    :ivar str certificate: URL to download certificate as a fullchain PEM.
    :ivar str finalize: URL to POST to to request issuance once all
        authorizations have "valid" status.
    :ivar datetime.datetime expires: When the order expires.
    :ivar .Error error: Any error that occurred during finalization, if applicable.
    """
    identifiers = jose.Field('identifiers', omitempty=True)
    status = jose.Field('status', decoder=Status.from_json,
                        omitempty=True)
    authorizations = jose.Field('authorizations', omitempty=True)
    certificate = jose.Field('certificate', omitempty=True)
    finalize = jose.Field('finalize', omitempty=True)
    expires = fields.RFC3339Field('expires', omitempty=True)
    error = jose.Field('error', omitempty=True, decoder=Error.from_json)

    @identifiers.decoder
    def identifiers(value):  # pylint: disable=no-self-argument,missing-function-docstring
        return tuple(Identifier.from_json(identifier) for identifier in value)

class OrderResource(ResourceWithURI):
    """Order Resource.

    :ivar acme.messages.Order body:
    :ivar str csr_pem: The CSR this Order will be finalized with.
    :ivar authorizations: Fully-fetched AuthorizationResource objects.
    :vartype authorizations: `list` of `acme.messages.AuthorizationResource`
    :ivar str fullchain_pem: The fetched contents of the certificate URL
        produced once the order was finalized, if it's present.
    :ivar alternative_fullchains_pem: The fetched contents of alternative certificate
        chain URLs produced once the order was finalized, if present and requested during
        finalization.
    :vartype alternative_fullchains_pem: `list` of `str`
    """
    body = jose.Field('body', decoder=Order.from_json)
    csr_pem = jose.Field('csr_pem', omitempty=True)
    authorizations = jose.Field('authorizations')
    fullchain_pem = jose.Field('fullchain_pem', omitempty=True)
    alternative_fullchains_pem = jose.Field('alternative_fullchains_pem', omitempty=True)

@Directory.register
class NewOrder(Order):
    """New order."""
    resource_type = 'new-order'
