"""ACME errors."""
import typing
from typing import Any
from typing import List
from typing import Mapping
from typing import Set

from josepy import errors as jose_errors

# We import acme.messages only during type check to avoid circular dependencies. Type references
# to acme.message.* must be quoted to be lazily initialized and avoid compilation errors.
if typing.TYPE_CHECKING:
    from acme import messages  # pragma: no cover


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
    def __init__(self, nonce: str, error: Exception, *args: Any) -> None:
        super().__init__(*args)
        self.nonce = nonce
        self.error = error

    def __str__(self) -> str:
        return 'Invalid nonce ({0!r}): {1}'.format(self.nonce, self.error)


class MissingNonce(NonceError):
    """Missing nonce error.

    According to the specification an "ACME server MUST include an
    Replay-Nonce header field in each successful response to a POST it
    provides to a client (...)".

    :ivar headers: Mapping of HTTP headers

    """
    def __init__(self, headers: Mapping, *args: Any) -> None:
        super().__init__(*args)
        self.headers = dict(headers)

    def __str__(self) -> str:
        return ('Server response did not include a replay '
                'nonce, headers: {0} (This may be a service outage)'.format(
                    self.headers))


class PollError(ClientError):
    """Generic error when polling for authorization fails.

    This might be caused by either timeout (`exhausted` will be non-empty)
    or by some authorization being invalid.

    :ivar exhausted: Set of `.AuthorizationResource` that didn't finish
        within max allowed attempts.
    :ivar updated: Mapping from original `.AuthorizationResource`
        to the most recently updated one

    """
    def __init__(self, exhausted: Set['messages.AuthorizationResource'],
                 updated: Mapping['messages.AuthorizationResource',
                                  'messages.AuthorizationResource']
                 ) -> None:
        self.exhausted = exhausted
        self.updated = updated
        super().__init__()

    @property
    def timeout(self) -> bool:
        """Was the error caused by timeout?"""
        return bool(self.exhausted)

    def __repr__(self) -> str:
        return '{0}(exhausted={1!r}, updated={2!r})'.format(
            self.__class__.__name__, self.exhausted, self.updated)


class ValidationError(Error):
    """Error for authorization failures. Contains a list of authorization
    resources, each of which is invalid and should have an error field.
    """
    def __init__(self, failed_authzrs: List['messages.AuthorizationResource']) -> None:
        self.failed_authzrs = failed_authzrs
        super().__init__()


class TimeoutError(Error):  # pylint: disable=redefined-builtin
    """Error for when polling an authorization or an order times out."""


class IssuanceError(Error):
    """Error sent by the server after requesting issuance of a certificate."""

    def __init__(self, error: 'messages.Error') -> None:
        """Initialize.

        :param messages.Error error: The error provided by the server.
        """
        self.error = error
        super().__init__()


class ConflictError(ClientError):
    """Error for when the server returns a 409 (Conflict) HTTP status.

    In the version of ACME implemented by Boulder, this is used to find an
    account if you only have the private key, but don't know the account URL.

    Also used in V2 of the ACME client for the same purpose.
    """
    def __init__(self, location: str) -> None:
        self.location = location
        super().__init__()


class WildcardUnsupportedError(Error):
    """Error for when a wildcard is requested but is unsupported by ACME CA."""
