"""ACME protocol v02 messages."""
from letsencrypt.acme import challenges
from letsencrypt.acme import fields
from letsencrypt.acme import jose


class Error(jose.JSONObjectWithFields, Exception):
    """ACME error.

    https://tools.ietf.org/html/draft-ietf-appsawg-http-problem-00

    """

    ERROR_TYPE_NAMESPACE = 'urn:acme:error:'
    ERROR_TYPE_DESCRIPTIONS = {
        'malformed': 'The request message was malformed',
        'unauthorized': 'The client lacks sufficient authorization',
        'serverInternal': 'The server experienced an internal error',
        'badCSR': 'The CSR is unacceptable (e.g., due to a short key)',
    }

    # TODO: Boulder omits 'type' and 'instance', spec requires
    typ = jose.Field('type', omitempty=True)
    title = jose.Field('title', omitempty=True)
    detail = jose.Field('detail')
    instance = jose.Field('instance', omitempty=True)

    @typ.encoder
    def typ(value):  # pylint: disable=missing-docstring,no-self-argument
        return Error.ERROR_TYPE_NAMESPACE + value

    @typ.decoder
    def typ(value):  # pylint: disable=missing-docstring,no-self-argument
        # pylint thinks isinstance(value, Error), so startswith is not found
        # pylint: disable=no-member
        if not value.startswith(Error.ERROR_TYPE_NAMESPACE):
            raise jose.DeserializationError('Missing error type prefix')

        without_prefix = value[len(Error.ERROR_TYPE_NAMESPACE):]
        if without_prefix not in Error.ERROR_TYPE_DESCRIPTIONS:
            raise jose.DeserializationError('Error type not recognized')

        return without_prefix

    @property
    def description(self):
        """Hardcoded error description based on its type."""
        return self.ERROR_TYPE_DESCRIPTIONS[self.typ]


class _Constant(jose.JSONDeSerializable):
    """ACME constant."""
    __slots__ = ('name',)
    POSSIBLE_NAMES = NotImplemented

    def __init__(self, name):
        self.POSSIBLE_NAMES[name] = self
        self.name = name

    def to_json(self):
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


class Status(_Constant):
    """ACME "status" field."""
    POSSIBLE_NAMES = {}
STATUS_UNKNOWN = Status('unknown')
STATUS_PENDING = Status('pending')
STATUS_PROCESSING = Status('processing')
STATUS_VALID = Status('valid')
STATUS_INVALID = Status('invalid')
STATUS_REVOKED = Status('revoked')


class IdentifierType(_Constant):
    """ACME identifier type."""
    POSSIBLE_NAMES = {}
IDENTIFIER_FQDN = IdentifierType('dns')  # IdentifierDNS in Boulder


class Identifier(jose.JSONObjectWithFields):
    """ACME identifier.

    :ivar letsencrypt.acme.messages2.IdentifierType typ:

    """
    typ = jose.Field('type', decoder=IdentifierType.from_json)
    value = jose.Field('value')


class Resource(jose.ImmutableMap):
    """ACME Resource.

    :ivar letsencrypt.acme.messages2.ResourceBody body: Resource body.
    :ivar str uri: Location of the resource.

    """
    __slots__ = ('body', 'uri')


class ResourceBody(jose.JSONObjectWithFields):
    """ACME Resource Body."""


class TypedResourceBody(jose.TypedJSONObjectWithFields):
    """ACME Resource Body with type."""


class ResourceBody(jose.JSONObjectWithFields):
    """ACME Resource Body"""


class RegistrationResource(Resource):
    """Registration Resource.

    :ivar letsencrypt.acme.messages2.Registration body:
    :ivar str new_authzr_uri: URI found in the 'next' ``Link`` header
    :ivar str terms_of_service: URL for the CA TOS.

    """
    __slots__ = ('body', 'uri', 'new_authzr_uri', 'terms_of_service')


class Registration(ResourceBody):
    """Registration Resource Body.

    :ivar letsencrypt.acme.jose.jwk.JWK key: Public key.
    :ivar tuple contact: Contact information following ACME spec

    """

    # on new-reg key server ignores 'key' and populates it based on
    # JWS.signature.combined.jwk
    key = jose.Field('key', omitempty=True, decoder=jose.JWK.from_json)
    contact = jose.Field('contact', omitempty=True, default=())
    recovery_token = jose.Field('recoveryToken', omitempty=True)
    agreement = jose.Field('agreement', omitempty=True)


class ChallengeResource(Resource, jose.JSONObjectWithFields):
    """Challenge Resource.

    :ivar letsencrypt.acme.messages2.ChallengeBody body:
    :ivar str authzr_uri: URI found in the 'up' ``Link`` header.

    """
    __slots__ = ('body', 'authzr_uri')

    @property
    def uri(self):  # pylint: disable=missing-docstring,no-self-argument
        # bug? 'method already defined line None'
        # pylint: disable=function-redefined
        return self.body.uri


class Challenge(TypedResourceBody):
    """Challenge Resource Body.

    :ivar letsencrypt.acme.messages2.Status status:
    :ivar datetime.datetime validated:

    """
    TYPES = {}
    # __slots__ = ('chall',)
    uri = jose.Field('uri')
    status = jose.Field('status', decoder=Status.from_json)
    validated = fields.RFC3339Field('validated', omitempty=True)

    def to_json(self):
        jobj = super(Challenge, self).to_json()
        return jobj


class AuthorizationResource(Resource):
    """Authorization Resource.

    :ivar letsencrypt.acme.messages2.Authorization body:
    :ivar str new_cert_uri: URI found in the 'next' ``Link`` header

    """
    __slots__ = ('body', 'uri', 'new_cert_uri')


class Authorization(ResourceBody):
    """Authorization Resource Body.

    :ivar letsencrypt.acme.messages2.Identifier identifier:
    :ivar list challenges: `list` of `ChallengeBody`
    :ivar tuple combinations: Challenge combinations (`tuple` of `tuple`
        of `int`, as opposed to `list` of `list` from the spec).
    :ivar letsencrypt.acme.jose.jwk.JWK key: Public key.
    :ivar tuple contact:
    :ivar letsencrypt.acme.messages2.Status status:
    :ivar datetime.datetime expires:

    """

    identifier = jose.Field('identifier', decoder=Identifier.from_json)
    challenges = jose.Field('challenges', omitempty=True)
    combinations = jose.Field('combinations', omitempty=True)

    # TODO: acme-spec #92, #98
    key = Registration._fields['key']
    contact = Registration._fields['contact']

    status = jose.Field('status', omitempty=True, decoder=Status.from_json)
    # TODO: 'expires' is allowed for Authorization Resources in
    # general, but for Key Authorization '[t]he "expires" field MUST
    # be absent'... then acme-spec gives example with 'expires'
    # present... That's confusing!
    expires = fields.RFC3339Field('expires', omitempty=True)

    @challenges.decoder
    def challenges(value):  # pylint: disable=missing-docstring,no-self-argument
        return tuple(challenges.Challenge.from_json(chall) for chall in value)

    @property
    def resolved_combinations(self):
        """Combinations with challenges instead of indices."""
        return tuple(tuple(self.challenges[idx] for idx in combo)
                     for combo in self.combinations)


class CertificateRequest(jose.JSONObjectWithFields):
    """ACME new-cert request.

    :ivar letsencrypt.acme.jose.util.ComparableX509 csr:
        `M2Crypto.X509.Request` wrapped in `.ComparableX509`
    :ivar tuple authorizations: `tuple` of URIs (`str`)

    """
    csr = jose.Field('csr', decoder=jose.decode_csr, encoder=jose.encode_csr)
    authorizations = jose.Field('authorizations', decoder=tuple)


class CertificateResource(Resource):
    """Certificate Resource.

    :ivar letsencrypt.acme.jose.util.ComparableX509 body:
        `M2Crypto.X509.X509` wrapped in `.ComparableX509`
    :ivar str cert_chain_uri: URI found in the 'up' ``Link`` header
    :ivar tuple authzrs: `tuple` of `AuthorizationResource`.

    """
    __slots__ = ('body', 'uri', 'cert_chain_uri', 'authzrs')


class Revocation(jose.JSONObjectWithFields):
    """Revocation message.

    :ivar revoke: Either a `datetime.datetime` or `Revocation.NOW`.
    :ivar tuple authorizations: Same as `CertificateRequest.authorizations`

    """

    NOW = 'now'
    """A possible value for `revoke`, denoting that certificate should
    be revoked now."""

    revoke = jose.Field('revoke')
    authorizations = CertificateRequest._fields['authorizations']

    @revoke.decoder
    def revoke(value):  # pylint: disable=missing-docstring,no-self-argument
        if value == Revocation.NOW:
            return value
        else:
            return fields.RFC3339Field.default_decoder(value)

    @revoke.encoder
    def revoke(value):  # pylint: disable=missing-docstring,no-self-argument
        if value == Revocation.NOW:
            return value
        else:
            return fields.RFC3339Field.default_encoder(value)
