"""ACME protocol messages."""
import urlparse

from acme import challenges
from acme import fields
from acme import jose


class Error(jose.JSONObjectWithFields, Exception):
    """ACME error.

    https://tools.ietf.org/html/draft-ietf-appsawg-http-problem-00

    """
    ERROR_TYPE_NAMESPACE = 'urn:acme:error:'
    ERROR_TYPE_DESCRIPTIONS = {
        'badCSR': 'The CSR is unacceptable (e.g., due to a short key)',
        'badNonce': 'The client sent an unacceptable anti-replay nonce',
        'connection': 'The server could not connect to the client for DV',
        'dnssec': 'The server could not validate a DNSSEC signed domain',
        'malformed': 'The request message was malformed',
        'serverInternal': 'The server experienced an internal error',
        'tls': 'The server experienced a TLS error during DV',
        'unauthorized': 'The client lacks sufficient authorization',
        'unknownHost': 'The server could not resolve a domain name',
    }

    typ = jose.Field('type')
    title = jose.Field('title', omitempty=True)
    detail = jose.Field('detail')

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

    def __str__(self):
        if self.typ is not None:
            return ' :: '.join([self.typ, self.description, self.detail])
        else:
            return str(self.detail)


class _Constant(jose.JSONDeSerializable):
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

    def __ne__(self, other):
        return not self == other


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

    :ivar acme.messages.IdentifierType typ:

    """
    typ = jose.Field('type', decoder=IdentifierType.from_json)
    value = jose.Field('value')


class Resource(jose.JSONObjectWithFields):
    """ACME Resource.

    :ivar str uri: Location of the resource.
    :ivar acme.messages.ResourceBody body: Resource body.

    """
    body = jose.Field('body')


class ResourceWithURI(Resource):
    """ACME Resource with URI.

    :ivar str uri: Location of the resource.

    """
    uri = jose.Field('uri')  # no ChallengeResource.uri


class ResourceBody(jose.JSONObjectWithFields):
    """ACME Resource Body."""


class Registration(ResourceBody):
    """Registration Resource Body.

    :ivar acme.jose.jwk.JWK key: Public key.
    :ivar tuple contact: Contact information following ACME spec

    """
    # on new-reg key server ignores 'key' and populates it based on
    # JWS.signature.combined.jwk
    key = jose.Field('key', omitempty=True, decoder=jose.JWK.from_json)
    contact = jose.Field('contact', omitempty=True, default=())
    recovery_token = jose.Field('recoveryToken', omitempty=True)
    agreement = jose.Field('agreement', omitempty=True)

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

    @property
    def phone(self):
        """Phone."""
        assert len(self.phones) == 1
        return self.phones[0]

    @property
    def email(self):
        """Email."""
        assert len(self.emails) == 1
        return self.emails[0]


class RegistrationResource(ResourceWithURI):
    """Registration Resource.

    :ivar acme.messages.Registration body:
    :ivar str new_authzr_uri: URI found in the 'next' ``Link`` header
    :ivar str terms_of_service: URL for the CA TOS.

    """
    body = jose.Field('body', decoder=Registration.from_json)
    new_authzr_uri = jose.Field('new_authzr_uri')
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
    :ivar str authzr_uri: URI found in the 'up' ``Link`` header.

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
    :ivar acme.jose.jwk.JWK key: Public key.
    :ivar tuple contact:
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


class AuthorizationResource(ResourceWithURI):
    """Authorization Resource.

    :ivar acme.messages.Authorization body:
    :ivar str new_cert_uri: URI found in the 'next' ``Link`` header

    """
    body = jose.Field('body', decoder=Authorization.from_json)
    new_cert_uri = jose.Field('new_cert_uri')


class CertificateRequest(jose.JSONObjectWithFields):
    """ACME new-cert request.

    :ivar acme.jose.util.ComparableX509 csr:
        `OpenSSL.crypto.X509Req` wrapped in `.ComparableX509`
    :ivar tuple authorizations: `tuple` of URIs (`str`)

    """
    csr = jose.Field('csr', decoder=jose.decode_csr, encoder=jose.encode_csr)
    authorizations = jose.Field('authorizations', decoder=tuple)


class CertificateResource(ResourceWithURI):
    """Certificate Resource.

    :ivar acme.jose.util.ComparableX509 body:
        `OpenSSL.crypto.X509` wrapped in `.ComparableX509`
    :ivar str cert_chain_uri: URI found in the 'up' ``Link`` header
    :ivar tuple authzrs: `tuple` of `AuthorizationResource`.

    """
    cert_chain_uri = jose.Field('cert_chain_uri')
    authzrs = jose.Field('authzrs')


class Revocation(jose.JSONObjectWithFields):
    """Revocation message.

    :ivar .ComparableX509 certificate: `OpenSSL.crypto.X509` wrapped in
        `.ComparableX509`

    """
    certificate = jose.Field(
        'certificate', decoder=jose.decode_cert, encoder=jose.encode_cert)

    # TODO: acme-spec#138, this allows only one ACME server instance per domain
    PATH = '/acme/revoke-cert'
    """Path to revocation URL, see `url`"""

    @classmethod
    def url(cls, base):
        """Get revocation URL.

        :param str base: New Registration Resource or server (root) URL.

        """
        return urlparse.urljoin(base, cls.PATH)
