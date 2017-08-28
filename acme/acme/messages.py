"""ACME protocol messages."""
import collections
import six

from acme import challenges
from acme import errors
from acme import fields
from acme import jose
from acme import util

OLD_ERROR_PREFIX = "urn:acme:error:"
ERROR_PREFIX = "urn:ietf:params:acme:error:"

ERROR_CODES = {
    'badCSR': 'The CSR is unacceptable (e.g., due to a short key)',
    'badNonce': 'The client sent an unacceptable anti-replay nonce',
    'connection': ('The server could not connect to the client to verify the'
                   ' domain'),
    'dnssec': 'The server could not validate a DNSSEC signed domain',
    # deprecate invalidEmail
    'invalidEmail': 'The provided email for a registration was invalid',
    'invalidContact': 'The provided contact URI was invalid',
    'malformed': 'The request message was malformed',
    'rateLimited': 'There were too many requests of a given type',
    'serverInternal': 'The server experienced an internal error',
    'tls': 'The server experienced a TLS error during domain verification',
    'unauthorized': 'The client lacks sufficient authorization',
    'unknownHost': 'The server could not resolve a domain name',
}

ERROR_TYPE_DESCRIPTIONS = dict(
    (ERROR_PREFIX + name, desc) for name, desc in ERROR_CODES.items())

ERROR_TYPE_DESCRIPTIONS.update(dict(  # add errors with old prefix, deprecate me
    (OLD_ERROR_PREFIX + name, desc) for name, desc in ERROR_CODES.items()))


def is_acme_error(err):
    """Check if argument is an ACME error."""
    if isinstance(err, Error) and (err.typ is not None):
        return (ERROR_PREFIX in err.typ) or (OLD_ERROR_PREFIX in err.typ)
    else:
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

    def __str__(self):
        return b' :: '.join(
            part.encode('ascii', 'backslashreplace') for part in
            (self.typ, self.description, self.detail, self.title)
            if part is not None).decode()


class _Constant(jose.JSONDeSerializable, collections.Hashable):  # type: ignore
    """ACME constant."""
    __slots__ = ('name',)
    POSSIBLE_NAMES = NotImplemented

    def __init__(self, name):
        self.POSSIBLE_NAMES[name] = self
        self.name = name

    def to_partial_json(self):
        return self.name

    @classmethod
    def from_json(cls, value):
        if value not in cls.POSSIBLE_NAMES:
            raise jose.DeserializationError(
                '{0} not recognized'.format(cls.__name__))
        return cls.POSSIBLE_NAMES[value]

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
        terms_of_service = jose.Field('terms-of-service', omitempty=True)
        website = jose.Field('website', omitempty=True)
        caa_identities = jose.Field('caa-identities', omitempty=True)

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
            raise AttributeError(str(error) + ': ' + name)

    def __getitem__(self, name):
        try:
            return self._jobj[self._canon_key(name)]
        except KeyError:
            raise KeyError('Directory field not found')

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


class Registration(ResourceBody):
    """Registration Resource Body.

    :ivar acme.jose.jwk.JWK key: Public key.
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

    phone_prefix = 'tel:'
    email_prefix = 'mailto:'

    @classmethod
    def from_data(cls, phone=None, email=None, **kwargs):
        """Create registration resource from contact details."""
        details = list(kwargs.pop('contact', ()))
        if phone is not None:
            details.append(cls.phone_prefix + phone)
        if email is not None:
            details.append(cls.email_prefix + email)
        kwargs['contact'] = tuple(details)
        return cls(**kwargs)

    def _filter_contact(self, prefix):
        return tuple(
            detail[len(prefix):] for detail in self.contact
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
class NewRegistration(Registration):
    """New registration."""
    resource_type = 'new-reg'
    resource = fields.Resource(resource_type)


class UpdateRegistration(Registration):
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
    uri = jose.Field('uri')
    status = jose.Field('status', decoder=Status.from_json,
                        omitempty=True, default=STATUS_PENDING)
    validated = fields.RFC3339Field('validated', omitempty=True)
    error = jose.Field('error', decoder=Error.from_json,
                       omitempty=True, default=None)

    def to_partial_json(self):
        jobj = super(ChallengeBody, self).to_partial_json()
        jobj.update(self.chall.to_partial_json())
        return jobj

    @classmethod
    def fields_from_json(cls, jobj):
        jobj_fields = super(ChallengeBody, cls).fields_from_json(jobj)
        jobj_fields['chall'] = challenges.Challenge.from_json(jobj)
        return jobj_fields

    def __getattr__(self, name):
        return getattr(self.chall, name)


class ChallengeResource(Resource):
    """Challenge Resource.

    :ivar acme.messages.ChallengeBody body:
    :ivar unicode authzr_uri: URI found in the 'up' ``Link`` header.

    """
    body = jose.Field('body', decoder=ChallengeBody.from_json)
    authzr_uri = jose.Field('authzr_uri')

    @property
    def uri(self):  # pylint: disable=missing-docstring,no-self-argument
        # bug? 'method already defined line None'
        # pylint: disable=function-redefined
        return self.body.uri  # pylint: disable=no-member


class Authorization(ResourceBody):
    """Authorization Resource Body.

    :ivar acme.messages.Identifier identifier:
    :ivar list challenges: `list` of `.ChallengeBody`
    :ivar tuple combinations: Challenge combinations (`tuple` of `tuple`
        of `int`, as opposed to `list` of `list` from the spec).
    :ivar acme.messages.Status status:
    :ivar datetime.datetime expires:

    """
    identifier = jose.Field('identifier', decoder=Identifier.from_json)
    challenges = jose.Field('challenges', omitempty=True)
    combinations = jose.Field('combinations', omitempty=True)

    status = jose.Field('status', omitempty=True, decoder=Status.from_json)
    # TODO: 'expires' is allowed for Authorization Resources in
    # general, but for Key Authorization '[t]he "expires" field MUST
    # be absent'... then acme-spec gives example with 'expires'
    # present... That's confusing!
    expires = fields.RFC3339Field('expires', omitempty=True)

    @challenges.decoder
    def challenges(value):  # pylint: disable=missing-docstring,no-self-argument
        return tuple(ChallengeBody.from_json(chall) for chall in value)

    @property
    def resolved_combinations(self):
        """Combinations with challenges instead of indices."""
        return tuple(tuple(self.challenges[idx] for idx in combo)
                     for combo in self.combinations)


@Directory.register
class NewAuthorization(Authorization):
    """New authorization."""
    resource_type = 'new-authz'
    resource = fields.Resource(resource_type)


class AuthorizationResource(ResourceWithURI):
    """Authorization Resource.

    :ivar acme.messages.Authorization body:
    :ivar unicode new_cert_uri: Deprecated. Do not use.

    """
    body = jose.Field('body', decoder=Authorization.from_json)
    new_cert_uri = jose.Field('new_cert_uri', omitempty=True)


@Directory.register
class CertificateRequest(jose.JSONObjectWithFields):
    """ACME new-cert request.

    :ivar acme.jose.util.ComparableX509 csr:
        `OpenSSL.crypto.X509Req` wrapped in `.ComparableX509`

    """
    resource_type = 'new-cert'
    resource = fields.Resource(resource_type)
    csr = jose.Field('csr', decoder=jose.decode_csr, encoder=jose.encode_csr)


class CertificateResource(ResourceWithURI):
    """Certificate Resource.

    :ivar acme.jose.util.ComparableX509 body:
        `OpenSSL.crypto.X509` wrapped in `.ComparableX509`
    :ivar unicode cert_chain_uri: URI found in the 'up' ``Link`` header
    :ivar tuple authzrs: `tuple` of `AuthorizationResource`.

    """
    cert_chain_uri = jose.Field('cert_chain_uri')
    authzrs = jose.Field('authzrs')


@Directory.register
class Revocation(jose.JSONObjectWithFields):
    """Revocation message.

    :ivar .ComparableX509 certificate: `OpenSSL.crypto.X509` wrapped in
        `.ComparableX509`

    """
    resource_type = 'revoke-cert'
    resource = fields.Resource(resource_type)
    certificate = jose.Field(
        'certificate', decoder=jose.decode_cert, encoder=jose.encode_cert)
    reason = jose.Field('reason')
