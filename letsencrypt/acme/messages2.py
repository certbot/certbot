"""ACME protocol v02 messages."""
import jsonschema

from letsencrypt.acme import challenges
from letsencrypt.acme import errors
from letsencrypt.acme import fields
from letsencrypt.acme import jose
from letsencrypt.acme import other
from letsencrypt.acme import util


class Error(jose.JSONObjectWithFields, Exception):
    """ACME error.

    https://tools.ietf.org/html/draft-ietf-appsawg-http-problem-00

    """

    ERROR_TYPE_NAMESPACE = 'urn:acme:error:'
    ERROR_TYPE_DESCRIPTIONS = {
        "malformed": "The request message was malformed",
        "unauthorized": "The client lacks sufficient authorization",
        "serverInternal": "The server experienced an internal error",
        "badCSR": "The CSR is unacceptable (e.g., due to a short key)",
    }

    typ = jose.Field('type', omitempty=True)  # Boulder omits, spec requires
    title = jose.Field('title', omitempty=True)
    detail = jose.Field('detail')
    # Boulder omits, spec requires
    instance = jose.Field('instance', omitempty=True)

    @typ.encoder
    def typ(value):
        return ERROR_TYPE_NAMESPACE + value

    @typ.decoder
    def typ(value):
        if not value.startswith(ERROR_TYPE_NAMESPACE):
            raise errors.DeserializationError('Unrecognized error type')

        return value[len(ERROR_TYPE_NAMESPACE):]

    @property
    def description(self):
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
                '{} not recognized'.format(cls.__name__))
        return cls.POSSIBLE_NAMES[value]

    def __repr__(self):
        return '{0}({0})'.format(self.__class__.__name__, self.name)

    def __eq__(self, other):
        return isinstance(other, type(self)) and other.name == self.name


class Status(_Constant):
    """ACME "status" field."""
    POSSIBLE_NAMES = {}
StatusUnknown = Status('unknown')
StatusPending = Status('pending')
StatusProcessing = Status('processing')
StatusValid = Status('valid')
StatusInvalid = Status('invalid')
StatusRevoked = Status('revoked')


class IdentifierType(_Constant):
    """ACME identifier type."""
    POSSIBLE_NAMES = {}
IdentifierFQDN = IdentifierType('dns')  # IdentifierDNS in Boulder


class Identifier(jose.JSONObjectWithFields):
    """ACME identifier."""
    typ = jose.Field('type', decoder=IdentifierType.from_json)
    value = jose.Field('value')


class Resource(jose.ImmutableMap):
    """ACME Resource.

    :param body: Resource body.
    :type body: Instance of `ResourceBody` (subclass).

    :param str uri: Location of the resource.

    """
    __slots__ = ('body', 'uri')


class ResourceBody(jose.JSONObjectWithFields):
    """ACME Resource body."""


class RegistrationResource(Resource):
    """Registration resource.

    :ivar body: `Registration`
    :ivar str uri: URI of the resource.
    :ivar new_authz_uri: URI found in the 'next' Link header

    """
    __slots__ = ('body', 'uri', 'new_authz_uri', 'terms_of_service')


class Registration(ResourceBody):
    """Registration resource body."""

    # on new-reg key server ignores 'key' and populates it based on
    # JWS.signature.combined.jwk
    key = jose.Field('key', omitempty=True, decoder=jose.JWK.from_json)
    contact = jose.Field('contact', omitempty=True, default=())
    recovery_token = jose.Field('recoveryToken', omitempty=True)
    agreement = jose.Field('agreement', omitempty=True)


class ChallengeResource(Resource, jose.JSONObjectWithFields):
    """Challenge resource.

    :ivar body: `.challenges.Challenge`
    :ivar authz_uri: URI found in the 'up' Link header.

    """
    __slots__ = ('body', 'authz_uri')


class Challenge(ResourceBody):
    """Challenge resource body.

    .. todo::
       Confusingly, this has the same name as
       `challenges.Challenge`. Indeed, this class could be integrated
       with challenges.Challenge, but this way it would be confusing
       when compared to acme-spec, where all challenges are presented
       without 'uri', 'status', or 'validated' fields.

    """

    __slots__ = ('chall',)
    uri = jose.Field('uri')
    status = jose.Field('status', decoder=Status.from_json)
    validated = fields.RFC3339Field('validated', omitempty=True)

    def to_json(self):
        jobj = super(Challenge, self).to_json()
        jobj.update(self.chall.to_json())
        return jobj

    @classmethod
    def fields_from_json(cls, jobj):
        fields = super(Challenge, cls).fields_from_json(jobj)
        fields['chall'] = challenges.Challenge.from_json(jobj)
        return fields


class AuthorizationResource(Resource):
    """Authorization resource.

    :ivar body: `Authorization`
    :ivar new_cert_uri: URI found in the 'next' Link header

    """
    __slots__ = ('body', 'uri', 'new_cert_uri')


class Authorization(ResourceBody):
    """Authorization resource body.

    :ivar challenges: `list` of `Challenge`

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
        return tuple(
            ChallengeResource(body=Challenge.from_json(chall), authz_uri=None)
            for chall in value)

    @property
    def resolved_combinations(self):
        """Combinations with challenges instead of indices."""
        return tuple(tuple(self.challenges[idx] for idx in combo)
                     for combo in self.combinations)


class CertificateRequest(jose.JSONObjectWithFields):
    """ACME new-cert request.

    :ivar csr: `M2Crypto.X509.Request`

    """
    csr = jose.Field('csr', decoder=jose.decode_csr, encoder=jose.encode_csr)
    authorizations = jose.Field('authorizations', decoder=tuple)


class CertificateResource(Resource):
    """Authorization resource.

    :ivar body: `M2Crypto.X509.X509`
    :ivar cert_chain_uri: URI found in the 'up' Link header
    :ivar authzrs: `list` of `AuthorizationResource`.

    """
    __slots__ = ('body', 'uri', 'cert_chain_uri', 'authzrs')


class Revocation(jose.JSONObjectWithFields):
    """Revocation message."""

    NOW = 'now'

    revoke = jose.Field('revoke')
    authorizations = CertificateRequest._fields['authorizations']

    @revoke.decoder
    def revoke(value):
        if jobj == NOW:
            return jobj
        else:
            return RFC3339Field.default_decoder(value)

    @revoke.encoder
    def revoke(value):
        if jobj == NOW:
            return value
        else:
            return RFC3339Field.default_encoder(value)
