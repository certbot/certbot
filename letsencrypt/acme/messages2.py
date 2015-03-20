"""ACME protocol v02 messages."""
import jsonschema

from letsencrypt.acme import challenges
from letsencrypt.acme import errors
from letsencrypt.acme import jose
from letsencrypt.acme import other
from letsencrypt.acme import util


class Resource(jose.JSONObjectWithFields):
    """ACME Resource."""


class Error(object):
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

    typ = jose.Field('type')
    title = jose.Field('title', omitempty=True)
    detail = jose.Field('detail')
    instance = jose.Field('instance')

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


class Registration(Resource):
    """Registration resource."""

    # key will be ignored by server and taken from JWS instead
    key = jose.Field('key', omitempty=True, decoder=jose.JWK.from_json)
    contact = jose.Field('contact', omitempty=True, default=())
    recovery_token = jose.Field('recoveryToken', omitempty=True)


class Identifier(jose.JSONObjectWithFields):
    typ = jose.Field('type')
    value = jose.Field('value')

    FQDN = 'dns'  # TODO: acme-spec uses 'domain' in some examples,
                  # Boulder uses 'dns' though

class ChallengeWithMeta(jose.JSONObjectWithFields):

    __slots__ = ('body',)
    status = jose.Field('status')
    validated = jose.Field('validated', omitempty=True)
    uri = jose.Field('uri')

    def to_json(self):
        jobj = super(ChallengeWithMeta, self).to_json()
        jobj.update(self.body.to_json())
        return jobj

    @classmethod
    def fields_from_json(cls, jobj):
        fields = super(ChallengeWithMeta, cls).fields_from_json(jobj)
        fields['body'] = challenges.Challenge.from_json(jobj)
        return fields

class Authorization(Resource):
    class Status(object):
        VALID = frozenset(['pending', 'valid', 'invalid'])

    identifier = jose.Field('identifier', decoder=Identifier.from_json)

    # acme-spec marks 'key' as 'required', but new-authz does not need
    # to carry it, server will take 'key' from the 'jwk' found in the
    # JWS
    key = jose.Field('key', omitempty=True, decoder=jose.JWK.from_json)
    status = jose.Field('status', omitempty=True)
    challenges = jose.Field('challenges', omitempty=True)
    combinations = jose.Field('combinations', omitempty=True)

    # TODO: 'The client MAY provide contact information in the
    # "contact" field in this or any subsequent request.' ???

    # TODO: 'expires' is allowed for Authorization Resources in
    # general, but for Authorization '[t]he "expires" field MUST be
    # absent'... then acme-spec gives example with 'expires'
    # present... That's confusing!
    #expires = jose.Field('expires', omitempty=True)

    @property
    def resolved_combinations(self):
        """Combinations with challenges instead of indices."""
        return tuple(tuple(self.challenges[idx] for idx in combo)
                     for combo in self.combinations)

    @challenges.decoder
    def challenges(value):  # pylint: disable=missing-docstring,no-self-argument
        # TODO: acme-spec examples use hybrid between a list and a
        # dict: "challenges": [ "simpleHttps": {}, ... ], while
        # Boulder uses (more sane): "challenges": [{"type":
        # "simpleHttps", ...}, ...]

        # TODO: Server also returns the follwing:
        # u'status': u'pending', u'completed': u'0001-01-01T00:00:00Z'
        # "uri":"http://0.0.0.0:4000/acme/authz/vI_H5tJroyaGhappi8xBtpGYSYBvuIo3JIvakORaEJo?challenge=0"
        tuple((chall['status'], chall.get('validated'), chall['uri'])
              for chall in value)

        return tuple(ChallengeWithMeta.from_json(chall) for chall in value)


class NewCertificate(Resource):
    """ACME new certificate resource request."""

    csr = jose.Field('csr', decoder=jose.decode_csr, encoder=jose.encode_csr)
    authorizations = jose.Field('authorizations', decoder=tuple)


class Revocation(Resource):
    revoke = jose.Field('revoke')
    authorizations = NewCertificate.authorizations
