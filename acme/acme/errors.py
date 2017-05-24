"""ACME errors."""
from acme.jose import errors as jose_errors

MYPY = False
if MYPY:
    from typing import Any, Set, Mapping  # pylint: disable=import-error, unused-import
    from requests import Response  # pylint: disable=unused-import
    from acme.messages import AuthorizationResource as AR  # pylint: disable=unused-import


class Error(Exception):
    """Generic ACME error."""


class DependencyError(Error):
    """Dependency error"""


class SchemaValidationError(jose_errors.DeserializationError):
    """JSON schema ACME object validation error."""


class ClientError(Error):
    """Network error."""


class UnexpectedUpdate(ClientError):
    """Unexpected update error."""


class NonceError(ClientError):
    """Server response nonce error."""


class BadNonce(NonceError):
    """Bad nonce error."""
    def __init__(self, nonce, error, *args, **kwargs):
        # type: (str, Any, Any, Any) -> None
        super(BadNonce, self).__init__(*args, **kwargs)
        self.nonce = nonce
        self.error = error

    def __str__(self):
        return 'Invalid nonce ({0!r}): {1}'.format(self.nonce, self.error)


class MissingNonce(NonceError):
    """Missing nonce error.

    According to the specification an "ACME server MUST include an
    Replay-Nonce header field in each successful response to a POST it
    provides to a client (...)".

    :ivar requests.Response response: HTTP Response

    """
    def __init__(self, response, *args, **kwargs):
        # type: (Response, Any, Any) -> None
        super(MissingNonce, self).__init__(*args, **kwargs)
        self.response = response

    def __str__(self):
        return ('Server {0} response did not include a replay '
                'nonce, headers: {1} (This may be a service outage)'.format(
                    self.response.request.method, self.response.headers))


class PollError(ClientError):
    """Generic error when polling for authorization fails.

    This might be caused by either timeout (`exhausted` will be non-empty)
    or by some authorization being invalid.

    :ivar exhausted: Set of `.AuthorizationResource` that didn't finish
        within max allowed attempts.
    :ivar updated: Mapping from original `.AuthorizationResource`
        to the most recently updated one

    """
    def __init__(self, exhausted, updated):
        # type: (Set[AR], Mapping[AR, AR]) -> None
        self.exhausted = exhausted
        self.updated = updated
        super(PollError, self).__init__()

    @property
    def timeout(self):
        """Was the error caused by timeout?"""
        return bool(self.exhausted)

    def __repr__(self):
        return '{0}(exhausted={1!r}, updated={2!r})'.format(
            self.__class__.__name__, self.exhausted, self.updated)

class ConflictError(ClientError):
    """Error for when the server returns a 409 (Conflict) HTTP status.

    In the version of ACME implemented by Boulder, this is used to find an
    account if you only have the private key, but don't know the account URL.
    """
    def __init__(self, location):
        self.location = location
        super(ConflictError, self).__init__()

